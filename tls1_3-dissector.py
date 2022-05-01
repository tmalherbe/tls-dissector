#!/usr/bin/python3.9
# -*- coding: utf-8 -*-

import argparse
import base64
import binascii

from dissector_const import *
from dissector_globals import *
from dissector_utils import *

from scapy.all import *

# Some global variables to handle SSL/TLS state-machine
#

## which ciphersuite was selected by the server ? ##
selected_cipher_suite = 0x0000

## what is the TLS version selected by the server ? ##
selected_version = None

## global variable for the cryptographic material generation ##
client_random = None
server_random = None

server_handshake_secret = None
client_handshake_secret = None

encrypted_handshake = False

## global variable to store the keylogfile name ##
keylogfile = None

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
		mac_algorithm = "SHA"
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
	elif mac_algorithm == "SHA":
		mac_algorithm_keylen = 20

def derivate_crypto_handshake_material():
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

		server_handshake_line = keyfilecontent[1]
		server_handshake_line_token = server_handshake_line.split(' ')
		if len(server_handshake_line_token) < 3:
			print("Error - %r is corrupted" % keylogfile)
			fd.close()
			return

		server_handshake_secret_hex_raw = server_handshake_line_token[2]
		server_handshake_secret_hex = server_handshake_secret_hex_raw.strip()
		server_handshake_secret = binascii.unhexlify(server_handshake_secret_hex)

		client_handshake_line = keyfilecontent[4]
		client_handshake_line_token = client_handshake_line.split(' ')
		if len(client_handshake_line_token) < 3:
			print("Error - %r is corrupted" % keylogfile)
			fd.close()
			return

		client_handshake_secret_hex_raw = client_handshake_line_token[2]
		client_handshake_secret_hex = client_handshake_secret_hex_raw.strip()
		client_handshake_secret = binascii.unhexlify(client_handshake_secret_hex)

		fd.close()
		if debug == True:
			print("server_handshake_secret : %r\n" % server_handshake_secret)
			print("client_handshake_secret : %r\n" % client_handshake_secret)
		exit(0)

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

	get_mac_algo()
	get_mac_algo_keylen()

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
	derivate_crypto_handshake_material()
	print("  ServerHello sent, subsequent handshake messages will be encrypted") 
	
	return offset

# Parse an Handshake record
# - Note that an Handshake record can contain multiple handshake messages
#
def dissect_handshake_record(handshake_record):

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

# Parse an Application record
# Basically nothing to do, unless a keylogfile is used
#
def dissect_application_record(tls_record):

	print("  Application record")

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
