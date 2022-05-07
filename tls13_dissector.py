#!/usr/bin/python3.9
# -*- coding: utf-8 -*-

import argparse
import base64
import binascii

from dissector_const import *
from dissector_globals import *
from dissector_utils import *

from Cryptodome.Cipher import AES

from scapy.all import *

# Some global variables to handle SSL/TLS state-machine
#

## which ciphersuite was selected by the server ? ##
selected_cipher_suite = 0x0000

## which cipherAlgorithm was selected by the server ? ##
cipher_algorithm = ""

## which hash function is used by the key derivation algorithms ? ##
prf_algorithm = ""

## what is the cipherAlgorithm key length ? ##
cipher_algorithm_keylen = 0

## what is the cipherAlgorithm block length ? ##
cipher_algorithm_blocklen = 0

## what is the TLS version selected by the server ? ##
selected_version = None

## global variable for the cryptographic material generation ##
client_random = None
server_random = None

## A secret for the server, another one for the client ##
server_handshake_secret = None
client_handshake_secret = None

## global variable who becomes True juste after ServerHello           ##
## (at this point server starts sending encrypted handshake messages) ##
## and becomes false again when handshake is finished                 ##
encrypted_handshake = False

## cryptographic material for handshake ##
client_handshake_key = None
client_handshake_iv = None
server_handshake_key = None
server_handshake_iv = None

## cryptographic material for traffic ##
client_app_key = None
client_app_iv = None
server_app_key = None
server_app_iv = None

## sequence numbers for MAC/GCM tag ##
seq_num_cli = b''
seq_num_srv = b''

## global variable to store the keylogfile name ##
keylogfile = None

## set cipher_algorithm global state variable during ServerHello ##
def get_cipher_algo():
	global selected_cipher_suite
	global cipher_algorithm

	cipher_suite_name = cipher_suites[selected_cipher_suite]

	if cipher_suite_name.find('AES_128_GCM') != -1:
		cipher_algorithm = "AES_128_GCM"
	elif cipher_suite_name.find('AES_256_GCM') != -1:
		cipher_algorithm = "AES_256_GCM"
	elif cipher_suite_name.find('CHACHA20_POLY1305') != -1:
		cipher_algorithm = "CHACHA20_POLY1305"
	else:
		cipher_algorithm = ""
		print("%r is not supported, too bad" % cipher_suite_name)

## set prf_algorithm global state variable during ServerHello ##
def get_prf_algo():
	global selected_cipher_suite
	global prf_algorithm

	cipher_suite_name = cipher_suites[selected_cipher_suite]

	if cipher_suite_name.find('SHA256') != -1:
		prf_algorithm = "SHA256"
	elif cipher_suite_name.find('SHA384') != -1:
		prf_algorithm = "SHA384"
	else:
		prf_algorithm = ""
		print("%r is not supported, too bad" % cipher_suite_name)

## set cipher_algorithm_keylen global state variable during ServerHello ##
def get_cipher_algo_keylen():
	global cipher_algorithm
	global cipher_algorithm_keylen

	if cipher_algorithm == "AES_128_GCM":
		cipher_algorithm_keylen = 16
	elif cipher_algorithm == "AES_256_GCM":
		cipher_algorithm_keylen = 32

## set cipher_algorithm_blocklen global state variable during ServerHello ##
def get_cipher_algo_blocklen():
	global cipher_algorithm
	global cipher_algorithm_blocklen

	if cipher_algorithm == "AES_128_GCM" or cipher_algorithm == "AES_256_GCM":
		cipher_algorithm_blocklen = 16
	else:
		print("%r is not supported, too bad" % cipher_algorithm)

## set cipher_algorithm_saltlen global state variable during ServerHello ##
def get_cipher_algo_saltlen():
	global cipher_algorithm
	global cipher_algorithm_saltlen

	if cipher_algorithm == "AES_128_GCM" or cipher_algorithm == "AES_256_GCM":
		cipher_algorithm_saltlen = 4

## set prf_algorithm_keylen global state variable during ServerHello ##
def get_prf_algo_keylen():
	global prf_algorithm
	global prf_algorithm_keylen

	if prf_algorithm == "SHA384":
		prf_algorithm_keylen = 48
	elif prf_algorithm == "SHA256":
		prf_algorithm_keylen = 32

## xor 2 strings ##
def xor(x, y):
	if len(x) != len(y):
		print("error, x and y don't have the same length");
		exit(0)
	return bytes(a ^ b for a, b in zip(x, y))

## key derivation internals, 1 ##
def HKDF_Extract(salt, IKM, algo):
	h = hmac.new(salt, digestmod = algo)
	h.update(IKM)
	PRK = h.digest()
	print("PRK : %r" % binascii.hexlify(PRK))
	return PRK

## key derivation internals, 2 ##
def HKDF_Expand(PRK, info, L, algo):
	T = []
	T0 = b''
	T.append(T0)
	
	n = 1 + L // 32
	#print(n)
	
	for i in range(n):
		h = hmac.new(PRK, digestmod = algo)#SHA256)
		h.update(T[i] + info + (i+1).to_bytes(1, 'big'))
		T_i_plus = h.digest()
		T.append(T_i_plus)
	OKM = b''
	for i in range(len(T)):
		OKM += T[i]
	return OKM[:L]

## key derivation internals, 3 ##
def HKDF_Expand_Label(secret, label, context, L, algo):
	tmpLabel = b'tls13 ' + label
	HkdfLabel = L.to_bytes(2, 'big') + (len(tmpLabel)).to_bytes(1, 'big') + tmpLabel + context
	#print("HkdfLabel : %r" % binascii.hexlify(HkdfLabel))
	return HKDF_Expand(secret, HkdfLabel, L, algo)

## read secrets from keylogfile then generate keys&iv ##
def derivate_crypto_material():

	global client_handshake_key
	global client_handshake_iv
	global server_handshake_key
	global server_handshake_iv

	global client_app_key
	global client_app_iv
	global server_app_key
	global server_app_iv

	global seq_num_cli
	global seq_num_srv

	if keylogfile != None:
	
		if debug == True:
			print("going to generate handshake crypto material from %r" % keylogfile)

		try:
			fd = open(keylogfile, "r")
		except:
			print("could not open %r" % keylogfile)
			return

		keyfilecontent = fd.readlines()		
		if len(keyfilecontent) < 6:
			print("Error - %r is corrupted" % keylogfile)
			fd.close()
			return

		# read the SERVER_HANDSHAKE_TRAFFIC_SECRET
		server_handshake_line = keyfilecontent[1]
		server_handshake_line_token = server_handshake_line.split(' ')
		if len(server_handshake_line_token) < 3:
			print("Error - %r is corrupted" % keylogfile)
			fd.close()
			return

		server_handshake_secret_hex_raw = server_handshake_line_token[2]
		server_handshake_secret_hex = server_handshake_secret_hex_raw.strip()
		server_handshake_secret = binascii.unhexlify(server_handshake_secret_hex)

		# read the SERVER_TRAFFIC_SECRET
		server_app_line = keyfilecontent[3]
		server_app_line_token = server_app_line.split(' ')
		if len(server_app_line_token) < 3:
			print("Error - %r is corrupted" % keylogfile)
			fd.close()
			return

		server_app_secret_hex_raw = server_app_line_token[2]
		server_app_secret_hex = server_app_secret_hex_raw.strip()
		server_app_secret = binascii.unhexlify(server_app_secret_hex)

		# read the CLIENT_HANDSHAKE_TRAFFIC_SECRET
		client_handshake_line = keyfilecontent[4]
		client_handshake_line_token = client_handshake_line.split(' ')
		if len(client_handshake_line_token) < 3:
			print("Error - %r is corrupted" % keylogfile)
			fd.close()
			return

		client_handshake_secret_hex_raw = client_handshake_line_token[2]
		client_handshake_secret_hex = client_handshake_secret_hex_raw.strip()
		client_handshake_secret = binascii.unhexlify(client_handshake_secret_hex)

		# read the CLIENT_TRAFFIC_SECRET
		client_app_line = keyfilecontent[5]
		client_app_line_token = client_app_line.split(' ')
		if len(client_app_line_token) < 3:
			print("Error - %r is corrupted" % keylogfile)
			fd.close()
			return

		client_app_secret_hex_raw = client_app_line_token[2]
		client_app_secret_hex = client_app_secret_hex_raw.strip()
		client_app_secret = binascii.unhexlify(client_app_secret_hex)

		fd.close()

		if debug == True:
			print("server_handshake_secret : %r\n" % server_handshake_secret)
			print("client_handshake_secret : %r\n" % client_handshake_secret)
			print("server_app_secret : %r\n" % server_app_secret)
			print("client_app_secret : %r\n" % client_app_secret)
			print("PRF function : %r" % prf_algorithm)
			print("cipher_algorithm : %r" % cipher_algorithm)
			print("cipher_algorithm_keylen : %r" % cipher_algorithm_keylen)

		# HKDF_Expand_Label needs a label (!)
		key_label = b'key'
		iv_label = b'iv'

		# generate client handshake crypto stuffs
		client_handshake_key = HKDF_Expand_Label(client_handshake_secret, key_label, b'\x00', cipher_algorithm_keylen, prf_algorithm)
		client_handshake_iv = HKDF_Expand_Label(client_handshake_secret, iv_label, b'\x00', 12, prf_algorithm)

		# generate server handshake crypto stuffs
		server_handshake_key = HKDF_Expand_Label(server_handshake_secret, key_label, b'\x00', cipher_algorithm_keylen, prf_algorithm)
		server_handshake_iv = HKDF_Expand_Label(server_handshake_secret, iv_label, b'\x00', 12, prf_algorithm)

		if debug == True:
			print("client handshake key : %r" % binascii.hexlify(client_handshake_key))
			print("client handshake iv : %r" % binascii.hexlify(client_handshake_iv))
			print("server handshake key : %r" % binascii.hexlify(server_handshake_key))
			print("server handshake iv : %r" % binascii.hexlify(server_handshake_iv))

		# generate client app crypto stuffs
		client_app_key = HKDF_Expand_Label(client_app_secret, key_label, b'\x00', cipher_algorithm_keylen, prf_algorithm)
		client_app_iv = HKDF_Expand_Label(client_app_secret, iv_label, b'\x00', 12, prf_algorithm)

		# generate server app crypto stuffs
		server_app_key = HKDF_Expand_Label(server_app_secret, key_label, b'\x00', cipher_algorithm_keylen, prf_algorithm)
		server_app_iv = HKDF_Expand_Label(server_app_secret, iv_label, b'\x00', 12, prf_algorithm)

		if debug == True:
			print("client app key : %r" % binascii.hexlify(client_app_key))
			print("client app iv : %r" % binascii.hexlify(client_app_iv))
			print("server app key : %r" % binascii.hexlify(server_app_key))
			print("server app iv : %r" % binascii.hexlify(server_app_iv))

		if debug == True:
			print("derivate_crypto_material, reinitialization of sequence numbers")
		seq_num_cli = b'\x00\x00\x00\x00\x00\x00\x00\x00'
		seq_num_srv = b'\x00\x00\x00\x00\x00\x00\x00\x00'

# TLS records analysis functions
# These functions are sorted according to the record type value :
# - CCS (0x14)
# - Alert (0x15)
# - Handshake (0x16)
# - Application (0x17)

# Parse a ChangeCipherSpec record
#
def dissect_ccs_record(tls_record):
	print("  ChangeCipherSpec record")

# Parse an Alarm record
# Basically nothing to do
#
def dissect_alert_record(tls_record):
	print("  Alarm record")

# Handshake processing functions

# Set the selected_version global variable
#
def dissect_extension_supported_version(extension_content):

	global selected_version

    # ClientHello - we can have several supported versions
	if dissector_globals.is_from_client == True:
		supported_versions_number = extension_content[0] >> 1

		for i in range(supported_versions_number):
			supported_version = int.from_bytes(extension_content[1 + 2*i : 1 + 2*i + 2], 'big')

			print("  - supported version n°%r : %r (%r)" % (i, hex(supported_version), get_tls_version(supported_version)))

    # ServerHello - we shall have only one supported version
	else:
		supported_version_len =  extension_content[0]

		# The server supported version shall be on two bytes
		if len(extension_content) != 2:
		    print("  - ? supported version returned by the server is weird (len = %r)" % supported_version_len)

		# if TLSv1.3, the content content of this extension in ServerHello
		# Overrides the version number set in the ServerHello message
		supported_version = int.from_bytes(extension_content[0:2], 'big')
		selected_version = supported_version

		print("  - Server supported version : %r (%r)" % (hex(supported_version), get_tls_version(supported_version)))


# Parse an extensions set
#
def parse_extension(hello_message, offset):
	extension_total_len = int.from_bytes(hello_message[offset : offset + 2], 'big')
	offset += 2

	print("  extension total length : %r" % extension_total_len)

	remaining_len = extension_total_len

	while remaining_len > 0:
		extension_type = int.from_bytes(hello_message[offset : offset + 2], 'big')
		remaining_len -= 2
		offset += 2

		extension_len = int.from_bytes(hello_message[offset : offset + 2], 'big')
		remaining_len -= 2
		offset += 2

		extension_content = hello_message[offset : offset + extension_len]

		offset += extension_len
		remaining_len -= extension_len

		print("  - extension type : %r (%r)" % (extension_type, get_extension_type(extension_type)))
		print("  - extension length : %r" % extension_len)

		if debug == True:
		    print("  - extension content : %r" % extension_content)

		# switch over extension type to analyse the extension
		# supported_version extension
		if extension_type == 43:
		    dissect_extension_supported_version(extension_content)
		# encrypt_then_mac extension
		elif extension_type == 22 and dissector_globals.is_from_client == False:
		    global encrypt_then_mac
		    encrypt_then_mac = True
		    print("  => Server wants to use encrypt_then_mac !")

	return offset

# Parse a ClientHello message
#
def dissect_client_hello(hello_message):

	# reinitialize session state
	global client_random
	global server_random

	client_random = None
	server_random = None
	encrypted_handshake = False

	offset = 0

	packet_version = int.from_bytes(hello_message[offset : offset + 2], 'big')
	offset += 2

	# client_random
	random = hello_message[offset : offset + 32]
	client_random = random
	offset += 32
	
	# session_id
	session_id_len = hello_message[offset]
	offset += 1

	session_id = hello_message[offset : offset + session_id_len]
	offset += session_id_len
	
	# cipher suites
	cipher_suite_number = int.from_bytes(hello_message[offset : offset + 2], 'big') >> 1
	offset += 2

	cipher_suites = []
	for i in range(cipher_suite_number):
		cipher_suite = int.from_bytes(hello_message[offset : offset + 2], 'big')
		cipher_suites.append(cipher_suite)
		offset += 2

	# compression suites
	compression_suite_number = hello_message[offset]
	offset += 1

	compression_suites = []
	for i in range(compression_suite_number):
		compression_suite = hello_message[offset]
		compression_suites.append(compression_suite)
		offset += 1

	print("  ClientHello - TLS version : %r (%r)" % (hex(packet_version),  get_tls_version(packet_version)))
	print("  ClientHello - Random : %r" % random)

	if session_id_len > 0:
		print("  ClientHello - SessionID : %r" % session_id)
	else:
		print("  ClientHello - no SessionID")

	print("  ClientHello : %r CipherSuites :" % cipher_suite_number)
	get_cipher_suites(cipher_suites)

	print("  ClientHello : %r CompressionSuites :" % compression_suite_number)
	get_compression_suites(compression_suites)

	# ClientHello extensions
	parse_extension(hello_message, offset)

# Parse a ServerHello message
#
def dissect_server_hello(hello_message):

	offset = 0
	global selected_version
	global server_random
	global selected_cipher_suite
	global encrypted_handshake

	# TLS version selected by server
	packet_version = int.from_bytes(hello_message[offset : offset + 2], 'big')
	selected_version = packet_version
	offset += 2

	# server_random
	random = hello_message[offset : offset + 32]
	server_random = random
	offset += 32

	# session_id
	session_id_len = hello_message[offset]
	offset += 1

	session_id = hello_message[offset : offset + session_id_len]
	offset += session_id_len

	# CipherSuite chosen by server - set all the cipherSuite-related global variables
	selected_cipher_suite = int.from_bytes(hello_message[offset : offset + 2], 'big')
	get_cipher_algo()
	get_cipher_algo_keylen()
	get_cipher_algo_blocklen()
	get_cipher_algo_saltlen()

	get_prf_algo()
	get_prf_algo_keylen()

	offset += 2

	# compression suites
	compression_suite_number = hello_message[offset]
	offset += 1

	compression_suites = []
	for i in range(compression_suite_number):
		compression_suite = hello_message[offset]
		compression_suites.append(compression_suite)
		offset += 1
	
	print("  ServerHello - TLS version : %r (%r)" % (hex(packet_version),  get_tls_version(packet_version)))
	print("  ServerHello - Random : %r" % random)
	
	if session_id_len > 0:
		print("  ServerHello - SessionID : %r" % session_id)
	else:
		print("  ServerHello - no SessionID")
	
	print("  ServerHello - Selected CipherSuite : %s" % cipher_suites[selected_cipher_suite])

	if is_a_tls13_ciphersuite(selected_cipher_suite) == False:
		print("  A non-TLSv1.3 CipherSuite has been selected, analysis cannot continue with this tool...")
		exit(0)

	print("  ServerHello : %r CompressionSuites :" % compression_suite_number)
	get_compression_suites(compression_suites)

	# selected_version will be overriden here because in TLSv1.3 server tells which version
	# was chosen using this extension
	offset = parse_extension(hello_message, offset)

	print("  ServerHello - Server selected %s" % get_tls_version(selected_version))

	if selected_version != 0x0304:
		print("  TLSv1.3 hasn't been selected, analysis cannot continue with this tool...")
		exit(0)

	encrypted_handshake = True
	derivate_crypto_material()
	print("  ServerHello sent, subsequent handshake messages will be encrypted\n")
	
	return offset

# Parse an NewSessionTicket message
#
def dissect_new_session_ticket(hello_message):
	offset = 0

# Parse an EndOfEarlyData message
#
def dissect_end_of_early_data(hello_message):
	offset = 0

# Parse an EncryptedExtension message
#
def dissect_encrypted_extension(hello_message):

	offset = 0

	print("encrypted_extension : %r" % binascii.hexlify(hello_message[:4]))
	encrypted_extension_length = int.from_bytes(hello_message[offset : offset + 2], 'big')
	offset += 2

	print("len : %r" % encrypted_extension_length)
	print("encrypted extension : %r " % hello_message[offset : offset + encrypted_extension_length])
	
	offset += encrypted_extension_length
	return offset


# returns a base64-nicely-encoded certificate
#
def dump_b64_cert(certificate):
	b64_cert_raw = base64.b64encode(certificate)
	b64_cert = ""
	i = 0

	while i < len(b64_cert_raw):
		b64_cert_chunk = b64_cert_raw[i : i + 64]
		b64_cert += "  "
		b64_cert += b64_cert_chunk.decode('ascii')
		b64_cert += "\n"
		i += 64
	return b64_cert

# Parse a Certificate message
#
def dissect_certificates_chain(hello_message):

	offset = 0

	# Unlike previous version, TLSv1.3 certificate structure contains a opaque certificate_request_context<0..2^8-1>
	# We shamelessly consider that this substructure is always NULL
	# TODO : handle properly this certificate_request_context
	offset += 1

	certificate_count = 0
	certificates_len = int.from_bytes(hello_message[offset : offset + 3], 'big')
	offset += 3
	
	remaining_len = certificates_len

	print("  certificates chain length : %r" % certificates_len)

	while remaining_len > 0:
		certificate_len = int.from_bytes(hello_message[offset : offset + 3], 'big')
		offset += 3
		remaining_len -= 3

		certificate = hello_message[offset : offset + certificate_len]
		print("  certificate n°%r, %r (%r) bytes : \n%s" % (certificate_count, certificate_len, hex(certificate_len), dump_b64_cert(certificate)))

		offset += certificate_len
		remaining_len -= certificate_len

		# We can have extension after the certificate.
		# We consider we haven't any extension.
		# Yes, it's bad.
		offset += 2
		remaining_len -= 2

		certificate_count += 1

	print("  read all the certificates ! ")

	return offset

def dissect_certificate_verify(hello_message):
	offset = 0

# Parse a Finished message
#
def dissect_finished(hello_message):

	global seq_num_cli
	global seq_num_srv

	global encrypted_handshake
	global encrypted_app

	if dissector_globals.is_from_client == True:
		encrypted_handshake = False
		encrypted_app = True

		if debug == True:
		    print("  dissect_finished, reinitialization of sequence numbers")
		seq_num_cli = b'\x00\x00\x00\x00\x00\x00\x00\x00'
		seq_num_srv = b'\x00\x00\x00\x00\x00\x00\x00\x00'


# Parse an Handshake record
# - Note that an Handshake record can contain multiple handshake messages
#
def dissect_handshake_record(handshake_record):

	print("  Handshake record")#;print("%r"%binascii.hexlify(handshake_record));exit()

	# record total length
	record_len = len(handshake_record)

	# absolute offset in record
	offset = 0

	# message counter
	message_index = 0

	# loop over the record the dissect all the messages
	while offset < record_len:

		# We shall have at least 4 bytes
		# (content_type + length)
		if (record_len - offset) < 4:
			print("  Error: The Handshake record is too short (%r remaining bytes)" % (record_len - offset))
			exit(0)

		# Read content_type (1 byte) and length (3 bytes)
		(message_type, message_len) = handshake_record_get_header(handshake_record, offset)

		# If message_type is unknown, message is probably an encrypted Finished 
		if message_type not in handshake_types:
			if dissector_globals.is_from_client:
			    print("  Handshake Type unknown, probably a Finished message")
			    message_len = record_len
			    message_type = 20
			else:
			    print("  Unknown handshake message (%r) !" % message_type)
		else:
			offset += 4
			print("  Handshake Type %r (%r)" % (message_type, get_handshake_type(message_type)))

		print("  Message length : %r" % message_len)
		handshake_message = handshake_record[offset : offset + message_len]

		if debug == True:
			print("  handshake_message %r : %r" % (message_index, handshake_message))
		offset += message_len

		# process the Handshake message
		# switch over the message_type
		# case 0 - HelloRequest
		if message_type == 0:
			dissect_hello_request(handshake_message)
		# case 1 - ClientHello
		elif message_type == 1:
			dissect_client_hello(handshake_message)
		# case 2 - ServerHello
		elif message_type == 2:
			dissect_server_hello(handshake_message)
		# case 4 - NewSessionTicket
		elif message_type == 4:
			dissect_new_session_ticket(handshake_message)
		# case 5 - EndofEarlyData
		elif message_type == 5:
			dissect_end_of_early_data(handshake_message)
		# case 8 - EncryptedExtension
		elif message_type == 8:
			dissect_encrypted_extension(handshake_message)
		# case 11 - Certificates
		elif message_type == 11:
			dissect_certificates_chain(handshake_message)
		# case 12 - ServerKeyExchange
		elif message_type == 12:
			dissect_server_key_exchange(handshake_message)
		# case 13 - CertificateRequest
		elif message_type == 13:
			dissect_certificate_request(handshake_message)
		# case 14 - ServerHelloDone
		elif message_type == 14:
			dissect_server_hello_done(handshake_message)
		# case 15 - CertificateVerify
		elif message_type == 15:
			dissect_certificate_verify(handshake_message)
		# case 16 - ClientKeyExchange
		elif message_type == 16:
			dissect_client_key_exchange(handshake_message)
		# case 20 - Finished
		elif message_type == 20:
			dissect_finished(handshake_message)
			offset += (record_len - 4)
		# case 24 - KeyUpdate
		elif message_type == 24:
			dissect_key_update(handshake_message)
		# case 254 - MessageHash
		elif message_type == 254:
			dissect_message_hash(handshake_message)
		# default case - can be an encrypted handshake message
		else:
			# if the handshake message is weird but no ChangeCipherSpec was seen,
			# ...then the message is just weird
			print("  Unknown handshake message (%r) !" % message_type)

		# increment the record counter
		message_index += 1

# Decrypt a TLSv1.3 application record
def decrypt_TLS_13_record(tls_record, key, iv):

	global seq_num_cli
	global seq_num_srv

	aead_ciphertext = tls_record

	# get the sequence number for the nonce
	if dissector_globals.is_from_client:
		seq_num = seq_num_cli
	else:
		seq_num = seq_num_srv

	# Unlike the partially-explicit nonce in TLSv1.2,
	# The TLSv1.3 nonce is the sequence number xored with the IV
	nonce = xor(iv, b'\x00\x00\x00\x00' + seq_num)
	additional_data =  b'\x17' + b'\x03\x03' + (len(aead_ciphertext)).to_bytes(2, 'big')

	cipher = AES.new(key, AES.MODE_GCM, nonce)
	cipher.update(additional_data)
	plaintext = cipher.decrypt(aead_ciphertext[: - cipher_algorithm_blocklen])

	# in TLSv1.3 the last encrypted byte indicates the message type
	plaintext_type = plaintext[-1]
	plaintext = plaintext[:-1]

	if debug == True:
		print("  seq_num : %r " % binascii.hexlify(seq_num))
		print("  nonce : %r" % binascii.hexlify(nonce))
		print("  tag from packet : %r (%r bytes)" % ((binascii.hexlify(aead_ciphertext[- cipher_algorithm_blocklen : ])), len(aead_ciphertext[- cipher_algorithm_blocklen : ])))
	print("  plaintext : %r" % plaintext)
	print("  plaintext type : %r" % get_content_type(plaintext_type))

	# increment sequence number
	seq_num_int = int.from_bytes(seq_num, 'big')
	seq_num_int += 1
	seq_num = seq_num_int.to_bytes(8, 'big')
	if dissector_globals.is_from_client:
		seq_num_cli = seq_num
	else:
		seq_num_srv = seq_num

	# decrypt the ciphertext is good, but check the tag is even better
	try:
		tag = cipher.verify(aead_ciphertext[- cipher_algorithm_blocklen : ])
		print("  GCM tag is correct :-)")

		# if the GCM tag agrees on it,
		# we can analyze the decrypted content
		if plaintext_type == 22:
			print("  Going to parse the decrypted handshake :-)")
			dissect_handshake_record(plaintext)

	except ValueError:
		print("  GCM tag is not correct :-(")

# Parse an Application record
# Basically nothing to do, unless a keylogfile is used
#
def dissect_application_record(tls_record,):

	print("  Application record")

	# if handshake is not finished yet,
	# use handshake crypto material...
	if encrypted_handshake == True:
		if dissector_globals.is_from_client:
			key = client_handshake_key
			iv = client_handshake_iv
		else:
			key = server_handshake_key
			iv = server_handshake_iv
	# otherwise use traffic crypto material
	elif encrypted_app == True:
		if dissector_globals.is_from_client:
			key = client_app_key
			iv = client_app_iv
		else:
			key = server_app_key
			iv = server_app_iv
	else:
		print("  Application record - no key to decrypt, too bad!")
		return
	decrypt_TLS_13_record(tls_record, key, iv)

# loop over the TCP payload
# to dissect all the TLS records
#
def dissect_tls_packet(packet, index):

	global previous_packet_fragmented
	global previous_offset
	global previous_tls_packet_index
	global previous_record_index

	# check IP&TCP layers
	check_tcpip_layer(packet, index)
	#get_packet_direction()

	tls_packet = bytes(packet[TCP].payload)

	# record counter
	record_index = 0

	if previous_packet_fragmented != None:
		print("TLS traffic is fragmented into several TCP packets")

		# Concatenate the data current TCP packet
		# at the end of data from previous TCP packet
		tls_packet = previous_packet_fragmented + tls_packet

		# TLS packet index is the same as for previous TCP packet
		index = previous_tls_packet_index

		# record counter initialized to value of previous record counter
		record_index = previous_record_index

	tls_packet_len = len(tls_packet)

	print("TLS packet %r, length %r" % (index, tls_packet_len))
	get_packet_direction()

	# absolute offset in TCP payload
	# if TLS packet is fragmented
	# we initialize the 'offset' cursor where we stopped the analysis
	# on the previous TCP packet
	offset = previous_offset

	# loop over all TLS records in the packet
	while offset < tls_packet_len:

		# We shall have at least 5 bytes
		# (content_type + version + length)
		if (tls_packet_len - offset) < 5:
			print("Error: The TLS record in packet n°%r is too short (%r remaining bytes)" % (index, tls_packet_len - offset))
			exit(0)

		# get the content type - 1 byte
		tls_content_type = tls_packet[offset]
		offset += 1

		# get the version (2 bytes) and the packet length (2 bytes)
		(record_version, record_len) = tls_packet_get_header(tls_packet, offset)
		offset += 4

		print(" TLS packet n°%r, record n°%r :" % (index, record_index))
		print(" packet version : %r (%r)" % (hex(record_version), get_tls_version(record_version)))
		print(" tls_content_type %r" % get_content_type(tls_content_type))
		print(" record length : %r" % record_len)

		# if fragmentation is detected we stop the analysis
		# and store the analysis state for the next packet
		if (tls_packet_len - offset < record_len):
			print("TLS packet seems to be fragmented across several TCP segments...")

			previous_packet_fragmented = tls_packet
			previous_offset = offset - 5
			previous_tls_packet_index = index
			previous_record_index = record_index
			break

		tls_record = tls_packet[offset : offset + record_len]
		offset += record_len

		if debug == True:
			print(" tls_record %r : %r" % (record_index, tls_record))

		# process the TLS record
		# switch over the tls_content_type
		# case 1 - CCS
		if tls_content_type == 20:
			dissect_ccs_record(tls_record)
		# case 2 - Alert
		elif tls_content_type == 21:
			dissect_alert_record(tls_record)
		# case 3 - Handshake
		elif tls_content_type == 22:
			dissect_handshake_record(tls_record)
		# case 4 - Application Data
		elif tls_content_type == 23:
			dissect_application_record(tls_record)
		# default case
		else:
			print("packet n°%r, record n°%r : unknown type (%r)" % (index, record_index, tls_content_type))

		# increment the record counter
		record_index += 1

		# Reaching the end of the record means
		# fragmentation is finished - if any
		if offset == tls_packet_len:
			previous_offset = 0
			previous_packet_fragmented = None
			previous_tls_packet_index = 0
			previous_record_index = 0

	print("");

def main():

	parser = argparse.ArgumentParser()

	parser.add_argument("-p", "--pcap",
								required = True,
								help = "TLSv1.3 traffic to dissect.The pcap file. This pcap is supposed to contain only 1 TLSv1.3/TCP stream, and the 1st frame shall be the emitted by the client",
								type = str)

	parser.add_argument("-k", "--keylogfile",
								required = False,
								help = "The file containing master secret & crypto stuffs to decrypt the traffic. This file comes from openssl s_client --keylogfile",
								type = str)

	parser.add_argument("-d", "--debug",
								required = False,
								help = "activate debugging with -d / --debug",
								action="store_true")

	global debug
	args = parser.parse_args()
	pcap_path = args.pcap
	debug = args.debug

	# open the pcap
	try:
		pcap = rdpcap(pcap_path)
	except:
		print("a problem occured while opening %r" % pcap_path)
		exit(0)

	# get the client & server IP addresses
	if pcap[0].haslayer(IP): 
		dissector_globals.addr_client = pcap[0][IP].src
		dissector_globals.addr_server = pcap[0][IP].dst
	elif pcap[0].haslayer(IPv6):
		dissector_globals.addr_client = pcap[0][IPv6].src
		dissector_globals.addr_server = pcap[0][IPv6].dst	
	else:
		print("Error: first packet doesn't have any IP layer")
		exit(0)

	# by assumption, first packet is from client to server
	is_from_client = True

	# there is no key exchange algorithm at the very begining
	key_exchange_algorithm = ""

	# set the keylogfile if any
	global keylogfile
	keylogfile = args.keylogfile

	# let's dissect every packet in the pcap !
	for i in range(len(pcap)):
		dissect_tls_packet(pcap[i], i)

if __name__ == '__main__':
	main()
