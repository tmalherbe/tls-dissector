#!/usr/bin/python3.9
# -*- coding: utf-8 -*-

import argparse
import base64
import binascii

from dissector_const import *
from dissector_globals import *
from dissector_utils import *

from Cryptodome.Hash import HMAC as hmac, MD5, SHA1, SHA256, SHA384
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

from scapy.all import *

# Some global variables to handle SSL/TLS state-machine
#

## global variable set to True when a ClientHello is seen ##
## and set to False when handshake is finished            ##
handshake_has_started = False

## has the client/server finished the handshake ? ##
client_finished_handshake = False
server_finished_handshake = False

## what is the key exchange algorithm ? ##
key_exchange_algorithm = ""

## which ciphersuite was selected by the server ? ##
selected_cipher_suite = 0x0000

## which cipherAlgorithm was selected by the server ? ##
cipher_algorithm = ""

## which macAlgorithm was selected by the server ? ##
mac_algorithm = ""

## what is the cipherAlgorithm key length ? ##
cipher_algorithm_keylen = 0

## what is the cipherAlgorithm block length ? ##
cipher_algorithm_blocklen = 0

## if AEAD is used, what is the salt length ? ##
cipher_algorithm_saltlen = 0

## what is the macAlgorithm key length ? ##
mac_algorithm_keylen = 0

## what is the TLS version selected by the server ? ##
selected_version = None

## global variable for the cryptographic material generation ##
client_random = None
server_random = None
master_secret = None

## global variable for the cryptographic material ##
key_block = None

## global variable to store the keylogfile name ##
keylogfile = None

## in TLSv1.0 - 1st application record uses an IV coming from key_block ##
## and following records use the end of the previous record as an IV    ##
is_first_block_cli = True
is_first_block_srv = True
last_iv_cli = None
last_iv_srv = None

## Have client&server chosen to encrypt then mac ? ##
## (by default TLS uses mac then encrypt)          ##
encrypt_then_mac = False

## sequence numbers for MAC/GCM tag ##
seq_num_cli = b''
seq_num_srv = b''

## set cipher_algorithm global state variable during ServerHello ##
def get_cipher_algo():
	global selected_cipher_suite
	global cipher_algorithm

	cipher_suite_name = cipher_suites[selected_cipher_suite]

	if cipher_suite_name.find('AES_128_CBC') != -1:
		cipher_algorithm = "AES_128_CBC"
	elif cipher_suite_name.find('AES_256_CBC') != -1:
		cipher_algorithm = "AES_256_CBC"
	elif cipher_suite_name.find('AES_128_GCM') != -1:
		cipher_algorithm = "AES_128_GCM"
	elif cipher_suite_name.find('AES_256_GCM') != -1:
		cipher_algorithm = "AES_256_GCM"
	elif cipher_suite_name.find('AES_128_CCM') != -1:
		cipher_algorithm = "AES_128_CCM"
	elif cipher_suite_name.find('AES_256_CCM') != -1:
		cipher_algorithm = "AES_256_CCM"
	elif cipher_suite_name.find('CHACHA20_POLY1305') != -1:
		cipher_algorithm = "CHACHA20_POLY1305"
	else:
		cipher_algorithm = ""
		print("%r is not supported, too bad" % cipher_suite_name)

## set mac_algorithm global state variable during ServerHello ##
def get_mac_algo():
	global selected_cipher_suite
	global mac_algorithm

	cipher_suite_name = cipher_suites[selected_cipher_suite]

	if cipher_suite_name.find('SHA256') != -1:
		mac_algorithm = "SHA256"
	elif cipher_suite_name.find('SHA384') != -1:
		mac_algorithm = "SHA384"
	elif cipher_suite_name.find('SHA') != -1:
		mac_algorithm = "SHA1"
	else:
		mac_algorithm = ""
		print("%r is not supported, too bad" % cipher_suite_name)

## set cipher_algorithm_keylen global state variable during ServerHello ##
def get_cipher_algo_keylen():
	global cipher_algorithm
	global cipher_algorithm_keylen

	if cipher_algorithm == "AES_128_CBC":
		cipher_algorithm_keylen = 16
	elif cipher_algorithm == "AES_256_CBC":
		cipher_algorithm_keylen = 32
	elif cipher_algorithm == "AES_128_GCM":
		cipher_algorithm_keylen = 16
	elif cipher_algorithm == "AES_256_GCM":
		cipher_algorithm_keylen = 32

## set cipher_algorithm_blocklen global state variable during ServerHello ##
def get_cipher_algo_blocklen():
	global cipher_algorithm
	global cipher_algorithm_blocklen

	if cipher_algorithm == "AES_128_CBC" or cipher_algorithm == "AES_256_CBC":
		cipher_algorithm_blocklen = 16

	if cipher_algorithm == "AES_128_GCM" or cipher_algorithm == "AES_256_GCM":
		cipher_algorithm_blocklen = 16

## set cipher_algorithm_saltlen global state variable during ServerHello ##
def get_cipher_algo_saltlen():
	global cipher_algorithm
	global cipher_algorithm_saltlen

	if cipher_algorithm == "AES_128_GCM" or cipher_algorithm == "AES_256_GCM":
		cipher_algorithm_saltlen = 4

## set mac_algorithm_keylen global state variable during ServerHello ##
def get_mac_algo_keylen():
	global mac_algorithm
	global mac_algorithm_keylen

	if mac_algorithm == "SHA384":
		mac_algorithm_keylen = 48
	elif mac_algorithm == "SHA256":
		mac_algorithm_keylen = 32
	elif mac_algorithm == "SHA1":
		mac_algorithm_keylen = 20

## set key_exchange_algorithm global state variable during ServerHello ##
def get_key_exchange_algorithm(selected_ciphersuite):
    ciphersuite_name = cipher_suites[selected_ciphersuite]
    global key_exchange_algorithm
    key_exchange_algorithm = ciphersuite_name.split('_')[1] + "_" + ciphersuite_name.split('_')[2]
    return key_exchange_algorithm

# Functions to compute session keys from master_secret
#

## xor 2 strings ##
def xor(x, y):
	if len(x) != len(y):
		print("error, x and y don't have the same length");
		exit(0)
	return bytes(a ^ b for a, b in zip(x, y))

## P_MD5 for TLSv1.0 & TLSv1.1(rfc 2246 section 5) ##
def P_MD5(secret, seed, n):

	global debug
	if debug == True:
	    print("")
	    print("MD5(%r, %r, %r)" % (secret, seed, n))

	# A[0] = seed
	A = []
	A.append(seed)

	p_hash = b''
	for i in range(n):
		# A[i + 1] = HMAC(secret, A[i])
		h = hmac.new(secret, digestmod = MD5)
		h.update(A[i])
		A_i_plus = h.digest()
		A.append(A_i_plus)
	for i in range(len(A) - 1):
		h = hmac.new(secret, digestmod = MD5)
		h.update(A[i+1] + seed)
		p_hash += h.digest()

	if debug == True:
		print("p_hash MD5 : %r (%r bytes)" % (p_hash, len(p_hash)))
	return p_hash

## P_SHA1 for TLSv1.0 & TLSv1.1(rfc 2246 section 5) ##
def P_SHA1(secret, seed, n):

	global debug
	if debug == True:
	    print("")
	    print("P_SHA1(%r, %r, %r)" % (secret, seed, n))

	# A[0] = seed
	A = []
	A.append(seed)

	p_hash = b''
	for i in range(n):
		# A[i + 1] = HMAC(secret, A[i])
		h = hmac.new(secret, digestmod = SHA1)
		h.update(A[i])
		A_i_plus = h.digest()
		A.append(A_i_plus)
	for i in range(len(A) - 1):
		h = hmac.new(secret, digestmod = SHA1)
		h.update(A[i+1] + seed)
		p_hash += h.digest()

	if debug == True:
		print("p_hash SHA1 : %r (%r bytes)" % (p_hash, len(p_hash)))
	return p_hash

## P_SHA256 for TLSv1.2 (rfc 5246 section 5) ##
def P_SHA256(secret, seed, n):

	global debug
	if debug == True:
	    print("")
	    print("P_SHA256(%r, %r, %r)" % (secret, seed, n))

	# A[0] = seed
	A = []
	A.append(seed)

	p_hash = b''
	for i in range(n):
		# A[i + 1] = HMAC(secret, A[i])
		h = hmac.new(secret, digestmod = SHA256)
		h.update(A[i])
		A_i_plus = h.digest()
		A.append(A_i_plus)
	for i in range(len(A) - 1):
		h = hmac.new(secret, digestmod = SHA256)
		h.update(A[i+1] + seed)
		p_hash += h.digest()

	if debug == True:
		print("p_hash SHA256 : %r (%r bytes)" % (p_hash, len(p_hash)))
	return p_hash

## P_SHA384 for TLSv1.2 (rfc 5246 section 5) ##
def P_SHA384(secret, seed, n):

	global debug
	if debug == True:
	    print("")
	    print("P_SHA384(%r, %r, %r)" % (secret, seed, n))

	# A[0] = seed
	A = []
	A.append(seed)

	p_hash = b''
	for i in range(n):
		# A[i + 1] = HMAC(secret, A[i])
		h = hmac.new(secret, digestmod = SHA384)
		h.update(A[i])
		A_i_plus = h.digest()
		A.append(A_i_plus)
	for i in range(len(A) - 1):
		h = hmac.new(secret, digestmod = SHA384)
		h.update(A[i+1] + seed)
		p_hash += h.digest()

	if debug == True:
		print("p_hash SHA384 : %r (%r bytes)" % (p_hash, len(p_hash)))
	return p_hash

## PRF (rfc 2246/5246 section 5) ##
def PRF(secret, label, seed):

	global debug
	if debug == True:
		print("PRF(%r, %r, %r)" % (secret, label, seed) )

	# TLSv1.0 & TLSv1.1 use a MD5+SHA1 based PRF
	if selected_version < 0x0303:
		l = len(secret)

		S1 = secret[:l//2]
		S2 = secret[l//2:]
		p_md5 = P_MD5(S1, label + seed, 20)
		p_sha1 = P_SHA1(S2, label + seed, 16)

		return xor(p_md5, p_sha1)
	# by default TLSv1.2 uses P_SHA256
	# another hash algorithm is used if explicitly
	# told by the chosen ciphersuite
	else:
		if mac_algorithm == 'SHA384':
			return P_SHA384(secret, label + seed, 20)
		else:
			return P_SHA256(secret, label + seed, 20)

## read master_secret from keylogfile and computes key_material using PRF() ##
def derivate_crypto_material():

	global key_block
	global debug
	global seq_num_cli
	global seq_num_srv

	if keylogfile != None and selected_version != None:

		if debug == True:
			print("going to generate crypto material for %r from %r" % (get_tls_version(selected_version), keylogfile))
		if client_random == None or server_random == None:
			print("client_random or server_random wasn't set !")
			return

		try:
			fd = open(keylogfile, "r")
		except:
			print("could not open %r" % keylogfile)
			return

		keyfilecontent = fd.readlines()
		if len(keyfilecontent) < 2:
			print("Error - %r is corrupted" % keylogfile)
			fd.close()
			return

		keyline = keyfilecontent[1]

		keyline_token = keyline.split(' ')
		if len(keyline_token) < 3:
			print("Error - %r is corrupted" % keylogfile)
			fd.close()
			return

		master_secret_hex_raw = keyline_token[2]
		master_secret_hex = master_secret_hex_raw.strip()
		master_secret = binascii.unhexlify(master_secret_hex)
		fd.close()

		if len(master_secret) != 48:
			print("Error - master secret is weird %r" % master_secret)
			return

		if debug == True:
			print("master_secret : %r\n" % master_secret)

		seed = server_random + client_random
		key_block = PRF(master_secret, b'key expansion', seed)

		seq_num_cli = b'\x00\x00\x00\x00\x00\x00\x00\x01'
		seq_num_srv = b'\x00\x00\x00\x00\x00\x00\x00\x01'

# TLS records analysis functions
# These functions are sorted according to the record type value :
# - CCS (0x14)
# - Alert (0x15)
# - Handshake (0x16)
# - Application (0x17)

# Parse a ChangeCipherSpec record
#
def dissect_ccs_record(tls_record):

	global client_finished_handshake
	global server_finished_handshake

	print("  ChangeCipherSpec record")

	if dissector_globals.is_from_client == True:
		client_finished_handshake = True
		print("Client has finished the handshake !")
	else:
		server_finished_handshake = True
		print("Server has finished the handshake !")

	if client_finished_handshake and server_finished_handshake:
		derivate_crypto_material()

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

# Parse an HelloRequest message
#
def dissect_hello_request(hello_message):
    offset = 0

# Parse a ClientHello message
#
def dissect_client_hello(hello_message):

	# reinitialize session state
	global client_finished_handshake
	global server_finished_handshake
	global handshake_has_started
	global client_random
	global server_random

	client_finished_handshake = False
	server_finished_handshake = False
	handshake_has_started = True
	client_random = None
	server_random = None

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

	get_mac_algo()
	get_mac_algo_keylen()

	offset += 2

	# key_exchange_algorithm
	get_key_exchange_algorithm(selected_cipher_suite)

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
		print("  ServerHello - KeyExchangeAlgorithm : %r" % key_exchange_algorithm)
	else:
		print("  A TLSv1.3 CipherSuite has been selected, analysis cannot continue with this tool...")
		exit(0)

	print("  ServerHello : %r CompressionSuites :" % compression_suite_number)
	get_compression_suites(compression_suites)

	# selected_version will be overriden here because in TLSv1.3 server tells which version
	# was chosen using this extension
	offset = parse_extension(hello_message, offset)

	print("  ServerHello - Server selected %s" % get_tls_version(selected_version))

	if selected_version == 0x0304:
		print("  TLSv1.3 has been selected, analysis cannot continue with this tool...")
		exit(0)

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

		certificate_count += 1

	print("  read all the certificates ! ")

	return offset

# Parse a ServerKeyExchange message
#
def dissect_server_key_exchange(hello_message):

	offset = 0

	if key_exchange_algorithm == "ECDHE_RSA":
		print("  key Exchange Algorithm : %s" % key_exchange_algorithm)
	elif key_exchange_algorithm == "DHE_DSS":
		print("  key Exchange Algorithm : %s" % key_exchange_algorithm)
	elif key_exchange_algorithm == "DHE_RSA":
		print("  key Exchange Algorithm : %s" % key_exchange_algorithm)
	elif key_exchange_algorithm == "RSA":
		print("  key Exchange Algorithm : %s" % key_exchange_algorithm)
	else:
		print("  key Exchange Algorithm : %s" % key_exchange_algorithm)
	return offset

# Parse a ClientKeyExchange message
#
def dissect_client_key_exchange(hello_message):

	offset = 0

	if key_exchange_algorithm == "ECDHE_RSA":
		print("  key Exchange Algorithm : %s" % key_exchange_algorithm)
	elif key_exchange_algorithm == "DHE_DSS":
		print("  key Exchange Algorithm : %s" % key_exchange_algorithm)
	elif key_exchange_algorithm == "DHE_RSA":
		print("  key Exchange Algorithm : %s" % key_exchange_algorithm)
	elif key_exchange_algorithm == "RSA":
		print("  key Exchange Algorithm : %s" % key_exchange_algorithm)
	else:
		print("  key Exchange Algorithm : %s" % key_exchange_algorithm)
	return offset

# Parse a Finished message
#
def dissect_finished(hello_message):

	global last_iv_srv
	global is_first_block_srv

	offset = 0

	# in TLSv1.0 the IV comes from key_material for the 1st record and then the end of the previous record
	# if message comes from server we need to remember the end of Finished message as the next IV.
	if encrypt_then_mac == False:
		if dissector_globals.is_from_client == False:
			last_iv_srv = hello_message[-cipher_algorithm_blocklen:]
			is_first_block_srv = False
	else:
		if dissector_globals.is_from_client == False:
			encrypted_record = hello_message[: -mac_algorithm_keylen]
			last_iv_srv = encrypted_record[-16:]
			is_first_block_srv = False

	return offset

# Parse a ServerHelloDone message
#
def dissect_server_hello_done(tls_packet):
	print("  server_hello_done - nothing to do")

# Parse an Handshake record
# - Note that an Handshake record can contain multiple handshake messages
#
def dissect_handshake_record(handshake_record):

	global handshake_has_started
	print("  Handshake record")

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
			if (dissector_globals.is_from_client and client_finished_handshake) or server_finished_handshake:
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
		if message_type == 0 and handshake_has_started:
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
			handshake_has_started = False
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

# TLS uses a PKCS#5 padding (\x03\x03\x03)
# prefixed with the padding length (therefore \x03\x03\x03\x03)
def unpad(padded_record):
	last_byte = padded_record[-1]

	if last_byte > cipher_algorithm_blocklen:
		print("  Padding Error ! Padding is longer than the cipher block size ! (%r)" % last_byte)
		return None
	elif last_byte > 0:
		for i in range(last_byte + 1):
			if padded_record[-i - 1] != last_byte:
				print("  Padding Error ! Padding is not correct (padded_record : %r)" % padded_record)
				return None

	unpadded_record = padded_record[: - last_byte - 1]
	return unpadded_record

# Decrypt a TLSv1.0 application record
# The record can be macced & encrypted (default) or encrypted & macced
def decrypt_TLS1_0_record(tls_record):

	global is_first_block_cli
	global is_first_block_srv

	global last_iv_cli
	global last_iv_srv

	global seq_num_cli
	global seq_num_srv

	if debug == True and encrypt_then_mac == True:
		print("  TLSv1.0 decryption - encrypt_then_mac is used")

	# get encryption_key and iv from key_material
	if dissector_globals.is_from_client == True:
		mac_key = key_block[:mac_algorithm_keylen]
		enc_key = key_block[2 * mac_algorithm_keylen : 2 * mac_algorithm_keylen + cipher_algorithm_keylen]
		seq_num = seq_num_cli
		# only 1st IV comes from key_material in TLSv1.0
		if is_first_block_cli:
			iv = key_block[2 * mac_algorithm_keylen + 2 * cipher_algorithm_keylen : 2 * mac_algorithm_keylen + 2 * cipher_algorithm_keylen + cipher_algorithm_blocklen]
			is_first_block_cli = False
		else:
			iv = last_iv_cli
	elif dissector_globals.is_from_client == False:
		mac_key = key_block[mac_algorithm_keylen : 2 * mac_algorithm_keylen]
		enc_key = key_block[2 * mac_algorithm_keylen + cipher_algorithm_keylen : 2 * mac_algorithm_keylen + 2 * cipher_algorithm_keylen]
		seq_num = seq_num_srv
		if is_first_block_srv:
			iv = key_block[2 * mac_algorithm_keylen + 2 * cipher_algorithm_keylen + cipher_algorithm_blocklen : 2 * mac_algorithm_keylen + 2 * cipher_algorithm_keylen + 2 * cipher_algorithm_blocklen]
			is_first_block_srv = False
		else:
			iv = last_iv_srv

	if debug == True:
		print("  iv : %r len(iv) %r" % (iv, len(iv)))
		print("  seq_num : %r " % seq_num)

	cipher = AES.new(enc_key, AES.MODE_CBC, iv)

	# default case
	# ciphertext = Encrypt(plaintext + padLen + padding + mac)
	# mac = MAC(seq_num + type + version + len(plaintext) + plaintext)
	if encrypt_then_mac == False:
		try:
			decrypted_record_padded = cipher.decrypt(tls_record)
			decrypted_record = unpad(decrypted_record_padded)

			# last plaintext bytes contains the MAC
			plaintext = decrypted_record[: - mac_algorithm_keylen]
			real_mac = decrypted_record[- mac_algorithm_keylen:]

			if debug == True:
				print("  Mac : %r" % real_mac)
				print("  Decrypted and padded data : %r" % decrypted_record)
			print("  Decrypted data: %r" % plaintext)

			# also with have to check the mac
			macced_data =  seq_num + b'\x17' + selected_version.to_bytes(2, 'big') + (len(plaintext)).to_bytes(2, 'big') + plaintext
			h = hmac.new(mac_key, digestmod = mac_algorithm)
			h.update(macced_data)
			computed_hmac = h.digest()

			if computed_hmac == real_mac:
				print("  GCM tag is correct :-)")
			else:
				print("  GCM tag is not correct :-(")

		except ValueError:
			print("  Decryption error !")

		# in TLSv1.0 end of ciphertext will be IV for next record
		if dissector_globals.is_from_client == True:
			last_iv_cli = tls_record[-16:]
		else:
			last_iv_srv = tls_record[-16:]
	# If encrypt_then_mac,
	# ciphertext = ENC(plaintext + padLen + padding)
	# ciphertext_mac = ciphertext + mac
	# mac = MAC(seq_num + type + version + len(ciphertext) + ciphertext)
	else:
		try:
			real_mac = tls_record[- mac_algorithm_keylen:]
			encrypted_record = tls_record[: -mac_algorithm_keylen]
			decrypted_record = cipher.decrypt(encrypted_record)
			plaintext = unpad(decrypted_record)

			if debug == True:
				print("  Mac : %r (%r bytes)" % (real_mac, len(real_mac)))
				print("  encrypted record with mac : %r (%r bytes)" % (encrypted_record, len(encrypted_record)))
				print("  decrypted_record : %r" % decrypted_record)
			print("  Decrypted data : %r" % plaintext)

			#also with have to check the mac
			macced_data =  seq_num + b'\x17' + selected_version.to_bytes(2, 'big') + (len(encrypted_record)).to_bytes(2, 'big') + encrypted_record
			h = hmac.new(mac_key, digestmod = mac_algorithm)
			h.update(macced_data)
			computed_hmac = h.digest()

			if computed_hmac == real_mac:
				print("  GCM tag is correct :-)")
			else:
				print("  GCM tag is not correct :-(")

		except ValueError as e:
			print("  Decryption error ! (%r)" % e)
		# in TLSv1.0 end of ciphertext will be IV for next record
		if dissector_globals.is_from_client == True:
			last_iv_cli = encrypted_record[-16:]
		else:
			last_iv_srv = encrypted_record[-16:]

	# increment sequence number
	seq_num_int = int.from_bytes(seq_num, 'big')
	seq_num_int += 1
	seq_num = seq_num_int.to_bytes(8, 'big')
	if dissector_globals.is_from_client:
		seq_num_cli = seq_num
	else:
		seq_num_srv = seq_num

# Decrypt a TLSv1.1 application record
# The record can be macced & encrypted (default) or encrypted & macced
def decrypt_TLS1_1_record(tls_record):

	global seq_num_cli
	global seq_num_srv

	# get encryption_key from key_material
	if dissector_globals.is_from_client == True:
		mac_key = key_block[:mac_algorithm_keylen]
		enc_key = key_block[2 * mac_algorithm_keylen : 2 * mac_algorithm_keylen + cipher_algorithm_keylen]
		seq_num = seq_num_cli
	elif dissector_globals.is_from_client == False:
		mac_key = key_block[mac_algorithm_keylen : 2 * mac_algorithm_keylen]
		enc_key = key_block[2 * mac_algorithm_keylen + cipher_algorithm_keylen : 2 * mac_algorithm_keylen + 2 * cipher_algorithm_keylen]
		seq_num = seq_num_srv

	iv = tls_record[:cipher_algorithm_blocklen]

	if debug == True:
		print("  iv : %r len(iv) %r" % (iv, len(iv)))
		print("  seq_num : %r " % seq_num)

	cipher = AES.new(enc_key, AES.MODE_CBC, iv)

	# default case
	# ciphertext_mac = iv + Encrypt(plaintext + padLen + padding + mac)
	# mac = MAC(seq_num + type + version + len(plaintext) + plaintext)
	if encrypt_then_mac == False:
		try:
			decrypted_record_padded = cipher.decrypt(tls_record)
			decrypted_record = unpad(decrypted_record_padded)

			# last plaintext bytes contains the MAC
			plaintext = decrypted_record[cipher_algorithm_blocklen: - mac_algorithm_keylen]
			real_mac = decrypted_record[- mac_algorithm_keylen:]

			if debug == True:
				print("  decrypted_record_padded : %r" % decrypted_record_padded)
				print("  decrypted_record : %r" % decrypted_record)
				print("  Mac : %r" % real_mac)
			print("  Decrypted data: %r" % plaintext)

			# also with have to check the mac
			macced_data =  seq_num + b'\x17' + selected_version.to_bytes(2, 'big') + (len(plaintext)).to_bytes(2, 'big') + plaintext
			h = hmac.new(mac_key, digestmod = mac_algorithm)
			h.update(macced_data)
			computed_hmac = h.digest()

			if computed_hmac == real_mac:
				print("  GCM tag is correct :-)")
			else:
				print("  GCM tag is not correct :-(")

		except ValueError:
			print("  Decryption error !")
	# If encrypt_then_mac,
	# ciphertext = iv + ENC(plaintext + padLen + padding)
	# ciphertext_mac = iv + ciphertext + mac
	# mac = MAC(seq_num + type + version + len(ciphertext) + ciphertext)
	else:
		try:
			# MAC is at the end of the encrypted record
			real_mac = tls_record[- mac_algorithm_keylen:]
			encrypted_record = tls_record[cipher_algorithm_blocklen: -mac_algorithm_keylen]
			decrypted_record = cipher.decrypt(encrypted_record)
			plaintext = unpad(decrypted_record)

			if debug == True:
				print("  Mac : %r (%r bytes)" % (real_mac, len(real_mac)))
				print("  encrypted record with mac : %r (%r bytes)" % (encrypted_record, len(encrypted_record)))
				print("  decrypted_record : %r" % decrypted_record)
			print("  Decrypted data : %r" % plaintext)

			#also with have to check the mac
			macced_data =  seq_num + b'\x17' + selected_version.to_bytes(2, 'big') + (len(tls_record[: -mac_algorithm_keylen])).to_bytes(2, 'big') + tls_record[: -mac_algorithm_keylen]
			h = hmac.new(mac_key, digestmod = mac_algorithm)
			h.update(macced_data)
			computed_hmac = h.digest()

			if computed_hmac == real_mac:
				print("  GCM tag is correct :-)")
			else:
				print("  GCM tag is not correct :-(")

		except ValueError as e:
			print("  Decryption error ! (%r)" % e)

	# increment sequence number
	seq_num_int = int.from_bytes(seq_num, 'big')
	seq_num_int += 1
	seq_num = seq_num_int.to_bytes(8, 'big')
	if dissector_globals.is_from_client:
		seq_num_cli = seq_num
	else:
		seq_num_srv = seq_num

# Decrypt an application record when GCM is used
def decrypt_TLS_GCM_record(tls_record):

	global seq_num_cli
	global seq_num_srv

	# get encryption_key and salt from key_material
	if dissector_globals.is_from_client == True:
		seq_num = seq_num_cli
		enc_key = key_block[ : cipher_algorithm_keylen]
		salt = key_block[2 * cipher_algorithm_keylen : 2 * cipher_algorithm_keylen + cipher_algorithm_saltlen]
	elif dissector_globals.is_from_client == False:
		seq_num = seq_num_srv
		enc_key = key_block[cipher_algorithm_keylen : 2 * cipher_algorithm_keylen]
		salt = key_block[2 * cipher_algorithm_keylen + cipher_algorithm_saltlen : 2 * cipher_algorithm_keylen + 2 * cipher_algorithm_saltlen]

	# we have tls_record = nonce_explicit + aead_ciphertext
	# - nonce_explicit is the 8-bytes explicit part of nonce/counter
	# - nonce_explicit is incremented for each tls_record
	# - final nonce is salt + nonce_explicit
	# - last bytes of aead_ciphertext contains the GCM tag
	nonce_explicit = tls_record[ : 8]
	aead_ciphertext = tls_record[8 : ]
	nonce = salt + nonce_explicit
	additional_data =  seq_num + b'\x17' + selected_version.to_bytes(2, 'big') + (len(aead_ciphertext) - cipher_algorithm_blocklen).to_bytes(2, 'big')

	# decrypt the ciphertext !
	cipher = AES.new(enc_key, AES.MODE_GCM, nonce)
	cipher.update(additional_data)
	plaintext = cipher.decrypt(aead_ciphertext[: - cipher_algorithm_blocklen])

	if debug == True:
		print("  seq_num : %r " % seq_num)
		print("  salt : %r len(salt) %r" % (salt, len(salt)))
		print("  nonce_explicit : %r" % binascii.hexlify(nonce_explicit))
		print("  nonce : %r" % nonce)
		print("  tag from packet : %r " % binascii.hexlify(aead_ciphertext[- cipher_algorithm_blocklen : ]))
	print("  plaintext : %r" % plaintext)

	# decrypt the ciphertext is good, but check the tag is even better
	try:
		tag = cipher.verify(aead_ciphertext[- cipher_algorithm_blocklen : ])
		print("  GCM tag is correct :-)")
	except ValueError:
		print("  GCM tag is not correct :-(")

	# increment sequence number
	seq_num_int = int.from_bytes(seq_num, 'big')
	seq_num_int += 1
	seq_num = seq_num_int.to_bytes(8, 'big')
	if dissector_globals.is_from_client:
		seq_num_cli = seq_num
	else:
		seq_num_srv = seq_num

# Parse an Application record
# Basically nothing to do, unless a keylogfile is used
#
def dissect_application_record(tls_record):

	print("  Application record")

	global selected_version

    # attempt decryption only if we have some key material
	if key_block != None:
		# TLSv1.0
		if selected_version == 0x0301:
			decrypt_TLS1_0_record(tls_record)
		# TLSv1.1
		elif selected_version == 0x0302:
			decrypt_TLS1_1_record(tls_record)
		# TLSv1.2
		elif selected_version == 0x0303:
			if (cipher_suites[selected_cipher_suite]).find('GCM') != -1:
			    decrypt_TLS_GCM_record(tls_record)
			else:
			    decrypt_TLS1_1_record(tls_record)

# global variables to store piece of a TLS packet
# in case this packet is fragmented into several
# TCP packets
#
previous_packet_fragmented = None
previous_offset = 0
previous_tls_packet_index = 0
previous_record_index = 0

# loop over the TCP payload
# to dissect all the TLS records
#
def dissect_tls_packet(packet, index):

	global previous_packet_fragmented
	global previous_offset
	global previous_tls_packet_index
	global previous_record_index

	# check IP&TCP layers
	check_tcpip_layer(packet, index, True)

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
								help = "TLS traffic to dissect.The pcap file. This pcap is supposed to contain only 1 TLS/TCP stream, and the 1st frame shall be the emitted by the client",
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
	dissector_globals.is_from_client = True

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
