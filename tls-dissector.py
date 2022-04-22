#!/usr/bin/python3.9
# -*- coding: utf-8 -*-

import argparse
from scapy.all import *

# several enums & their getters:
# - tls versions
# - records types
# - handshake messages types
# - cipher suites
# - handshake messages extensions
tls_versions = {
	0x0301: "TLSv1.0",
	0x0302: "TLSv1.1",
	0x0303: "TLSv1.2",
	0x0304: "TLSv1.3"
}

def get_tls_version(tls_version):
	try:
		return tls_versions[tls_version]
	except:
		print("tls_version %r is unknown" % hex(tls_version))

content_types = {
	20: "ChangeCipherSpec",
	21: "Alert",
	22: "Handshake",
	23: "Application Data"
}

def get_content_type(content_type):
	try:
		return content_types[content_type]
	except:
		print("content_type %r is unknown" % hex(content_type))

handshake_types = {
	0: "HelloRequest",
	1: "ClientHello",
	2: "ServerHello",
	4: "NewSessionTicket",
	5: "EndOfEarlyData",
	8: "EncryptedExtension",
	11: "Certificate",
	12: "ServerKeyExchange",
	13: "CertificateRequest",
	14: "ServerHelloDone",
	15: "CertificateVerify",
	16: "ClientKeyExchange",
	20: "Finished",
	24: "KeyUpdate",
	254: "MessageHash"
}

def get_handshake_type(handshake_type):
	try:
		return handshake_types[handshake_type]
	except:
		print("handshake_type %r is unknown" % hex(handshake_type))

cipher_suites = {
	0x0000: "TLS_NULL_WITH_NULL_NULL",

	# RSA-based cipher suites
	0x0001: "TLS_RSA_WITH_NULL_MD5",
	0x0002: "TLS_RSA_WITH_NULL_SHA",
	0x003B: "TLS_RSA_WITH_NULL_SHA256",
	0x0004: "TLS_RSA_WITH_RC4_128_MD5",
	0x0005: "TLS_RSA_WITH_RC4_128_SHA",
	0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",

	# Diffie-Hellman based cipher suites
	0x000D: "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
	0x0010: "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
	0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0030: "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
	0x0031: "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
	0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
	0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	0x0036: "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
	0x0037: "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
	0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
	0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	0x003E: " TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
	0x003F: "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
	0x0040: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
	0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	0x0068: "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
	0x0069: "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
	0x006A: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
	0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",

	# Anonymous Diffie-Hellman cipher suites
	0x0018: "TLS_DH_anon_WITH_RC4_128_MD5",
	0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
	0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
	0x003A: "TLS_DH_anon_WITH_AES_256_CBC_SHA",
	0x006C: "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
	0x006D: "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
	
	# TLSv1.3 cipher suites
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0x1304: "TLS_AES_128_CCM_SHA256",
	0x1305: "TLS_AES_128_CCM_8_SHA256",
	
	# ChaCha20-Poly1305 cipher suites - RFC 7905
	0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xCCAB: "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
	0xCCAC: "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
	0xCCAD: "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
	0xCCAE: "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256",

   # TLS Renegotiation indication cipher suite - RFC 5746
    0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",

   # TLS Fallback Signaling cipher suite - RFC 7507
	0x5600: "TLS_FALLBACK_SCSV",
   
   # TLS ECC-based cipher suites - RFC 4492 & 8422
	0xC001: "TLS_ECDH_ECDSA_WITH_NULL_SHA",
	0xC002: "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
	0xC003: "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0xC004: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
	0xC005: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
	0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
	0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0xC008: "TLS_ECDH_RSA_WITH_NULL_SHA",
	0xC00C: "TLS_ECDH_RSA_WITH_RC4_128_SHA",
	0xC00D: "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
	0xC00E: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
	0xC00F: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
	0xC010: "TLS_ECDHE_RSA_WITH_NULL_SHA",
	0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0xC015: "TLS_ECDH_anon_WITH_NULL_SHA",
	0xC016: "TLS_ECDH_anon_WITH_RC4_128_SHA",
	0xC017: "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
	0xC018: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
	0xC019: "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
	0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	
	# TLS AES-GCM cipher suites - RFC 5288
	0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	0x00A0: "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
	0x00A1: "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
	0x00A2: "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
	0x00A3: "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
	0x00A4: "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
	0x00A5: "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
	0x00A6: "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
	0x00A7: "TLS_DH_anon_WITH_AES_256_GCM_SHA384",

	# TLS AES-GCM cipher suites with SHA-256/384 - RFC 5289
	0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	0xC025: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
	0xC026: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
	0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	0xC029: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
	0xC02A: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
	0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xC02D: "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
	0xC02E: "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
	0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xC031: "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
	0xC032: "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"
}

def get_cipher_suites(cipher_suites_array):
	for cipher_suite in cipher_suites_array:
		try:
		    print("\t - " + cipher_suites[cipher_suite])
		except:
		    print("cipher_suite %r is unknown" % hex(cipher_suite))

def get_compression_suites(compression_suites_array):
	print("\t - %r" % compression_suites_array)

extension_types = {
	0: "server_name",
	1: "max_fragment_length",
	5: "status_request",
	10: "supported_groups",
	11: "ec_point_formats",
	13: "signature_algorithms",
	14: "use_srtp",
	15: "heartbeat",
	16: "application_layer_protocol_negotiation",
	18: "signed_certificate_timestamp",
	19: "client_certificate_type",
	20: "server_certificate_type",
	21: "padding",
	22: "encrypted_then_mac",
	23: "extended_master_secret",
	35: "session_ticket",
	41: "pre_shared_key",
	42: "early_data",
	43: "supported_versions",
	44: "cookie",
	45: "psk_key_exchange_modes",
	47: "certificate_authorities",
	48: "oid_filters",
	49: "post_handshake_auth",
	50: "signature_algorithms_cert",
	51: "key_share",
	65281: "renegotiation_info"
}

# Some global variables to handle SSL/TLS state-machine
#
# global variables for client & server addresses
addr_client = ""
addr_server = ""

# global variable set to True when a ClientHello is seen
# and set to False when handshake is finished
handshake_has_started = False

# global variables to check if handshake is finished
client_finished_handshake = False
server_finished_handshake = False

# global variable for the selected key exchange algorithm
key_exchange_algorithm = ""

# global variable set to True if message is client -> server
is_from_client = False

# global variable for the selected TLS version
selected_version = None

def get_extension_type(extension_type):
	try:
		return extension_types[extension_type]
	except:
		print("extension %r is unknown" % hex(extension_type))

# Some general purpose functions to :
# - Check if the TLS packet is client->server, server->client or Out Of Blue
# - Get the header of a TLS packet

# Parse the header of a TLS record
# This header shall contain:
# - 1 byte indicating the content type
# - 2 bytes indicating the record version
# - 2 bytes indicating the record length
#
def tls_packet_get_header(tls_packet, offset):
	packet_version = int.from_bytes(tls_packet[offset : offset + 2], 'big')
	packet_len = int.from_bytes(tls_packet[offset + 2 : offset + 4], 'big')
	return (packet_version, packet_len)

# Check IP/TCP layer:
# - IP4/IPv6 layer is mandatory
# - TCP layer is mandatory
# - Packet shall either be from client to server or from server to client
#
def check_tcpip_layer(packet, index):

	global is_from_client

	# decide if the packet is from client or from server
	if packet.haslayer(IP):
		if packet[IP].src == addr_client and packet[IP].dst == addr_server:
			print("client -> server")
			is_from_client = True
		elif packet[IP].dst == addr_client and packet[IP].src == addr_server:
			print("server -> client")
			is_from_client = False
		else:
			print("Error: packet %r doesn't belong to the TLS stream" % index)
			exit(0)
	elif packet.haslayer(IPv6):
		if packet[IPv6].src == addr_client and packet[IPv6].dst == addr_server:
			print("client -> server")
			is_from_client = True
		elif packet[IPv6].dst == addr_client and packet[IPv6].src == addr_server:
			print("server -> client")
			is_from_client = False
		else:
			print("Error: packet %r doesn't belong to the TLS stream" % index)
			exit(0)
	else:
		print("Error: packet %r doesn't have any IP layer" % index)
		exit(0)

	# we shall have a TCP layer !
	if not packet.haslayer(TCP):
		print("Error: packet %r doesn't have any TCP layer" % index)
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

	global client_finished_handshake
	global server_finished_handshake

	print("  ChangeCipherSpec record")

	if is_from_client == True:
		client_finished_handshake = True
		print("Client has finished the handshake !")
	else:
		server_finished_handshake = True
		print("Server has finished the handshake !")

# Parse an Alarm record
# Basically nothing to do
#
def dissect_alert_record(tls_record):
	print("  Alarm record")

# Handshake processing functions

# Parse the header of an handshake message
# This header shall contain:
# - 1 byte indicating the message type
# - 3 bytes indicating the message length
#
def handshake_record_get_header(handshake_record, offset):
	record_type = int.from_bytes(handshake_record[offset : offset + 1], 'big')
	record_len = int.from_bytes(handshake_record[offset + 1 : offset + 4], 'big')
	return (record_type, record_len)

def dissect_extension_supported_version(extension_content):

	global selected_version

	supported_versions_number = extension_content[0] >> 1

	for i in range(supported_versions_number):
		supported_version = int.from_bytes(extension_content[1 + 2*i : 1 + 2*i + 2], 'big')

		print("\t\t - supported version n°%r : %r (%r)" % (i, hex(supported_version), get_tls_version(supported_version)))

		# if TLSv1.3, the content content of this extension in ServerHello
		# Overrides the version number set in the ServerHello message
		if is_from_client == False and supported_versions_number == 1:
			selected_version = supported_version

# Parse an extensions set
#
def parse_extension(hello_message, offset):
	extension_total_len = int.from_bytes(hello_message[offset : offset + 2], 'big')
	offset += 2

	print("extension total length : %r" % extension_total_len)

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

		print("\t - extension type : %r (%r)" % (extension_type, get_extension_type(extension_type)))
		print("\t - extension length : %r" % extension_len)
		print("\t - extension content : %r" % extension_content)

		# switch over extension type to analyse the extension
		if extension_type == 43:
		    dissect_extension_supported_version(extension_content)

	return offset

# Parse an HelloRequest message
#
def dissect_hello_request(hello_message):
    offset = 0

# Parse a ClientHello message
#
def dissect_client_hello(hello_message):

	# reinitialize session keys
	global client_finished_handshake
	global server_finished_handshake
	global handshake_has_started

	client_finished_handshake = False
	server_finished_handshake = False
	handshake_has_started = True

	offset = 0

	packet_version = int.from_bytes(hello_message[offset : offset + 2], 'big')
	offset += 2
	
	random = hello_message[offset : offset + 32]
	offset += 32
	
	session_id_len = hello_message[offset]
	offset += 1

	session_id = hello_message[offset : offset + session_id_len]
	offset += session_id_len
	
	cipher_suite_number = int.from_bytes(hello_message[offset : offset + 2], 'big') >> 1
	offset += 2

	cipher_suites = []
	for i in range(cipher_suite_number):
		cipher_suite = int.from_bytes(hello_message[offset : offset + 2], 'big')
		cipher_suites.append(cipher_suite)
		offset += 2

	compression_suite_number = hello_message[offset]
	offset += 1

	compression_suites = []
	for i in range(compression_suite_number):
		compression_suite = hello_message[offset]
		compression_suites.append(compression_suite)
		offset += 1

	print("ClientHello - TLS version : %r (%r)" % (hex(packet_version),  get_tls_version(packet_version)))
	print("ClientHello - Random : %r" % random)
	
	if session_id_len > 0:
		print("ClientHello - SessionID : %r" % session_id)
	else:
		print("ClientHello - no SessionID")

	print("ClientHello : %r CipherSuites :" % cipher_suite_number)
	get_cipher_suites(cipher_suites)

	print("ClientHello : %r CompressionSuites :" % compression_suite_number)
	get_compression_suites(compression_suites)

	parse_extension(hello_message, offset)


# Get the key exchange algorithm from the the selected CipherSuite
#
def get_key_exchange_algorithm(selected_ciphersuite):
    ciphersuite_name = cipher_suites[selected_ciphersuite]
    global key_exchange_algorithm
    key_exchange_algorithm = ciphersuite_name.split('_')[1] + "_" + ciphersuite_name.split('_')[2]
    return key_exchange_algorithm

# Parse a ServerHello message
#
def dissect_server_hello(hello_message):

	offset = 0
	global selected_version

	packet_version = int.from_bytes(hello_message[offset : offset + 2], 'big')
	selected_version = packet_version
	offset += 2

	random = hello_message[offset : offset + 32]
	offset += 32

	session_id_len = hello_message[offset]
	offset += 1

	session_id = hello_message[offset : offset + session_id_len]
	offset += session_id_len

	selected_cipher_suite = int.from_bytes(hello_message[offset : offset + 2], 'big')
	offset += 2

	#key_exchange_algorithm
	get_key_exchange_algorithm(selected_cipher_suite)

	compression_suite_number = hello_message[offset]
	offset += 1

	compression_suites = []
	for i in range(compression_suite_number):
		compression_suite = hello_message[offset]
		compression_suites.append(compression_suite)
		offset += 1
	
	print("ServerHello - TLS version : %r (%r)" % (hex(packet_version),  get_tls_version(packet_version)))
	print("ServerHello - Random : %r" % random)
	
	if session_id_len > 0:
		print("ServerHello - SessionID : %r" % session_id)
	else:
		print("ServerHello - no SessionID")
	
	print("ServerHello - Selected CipherSuite : %r" % cipher_suites[selected_cipher_suite])
	print("ServerHello - KeyExchangeAlgorithm : %r" % key_exchange_algorithm)

	print("ServerHello : %r CompressionSuites :" % compression_suite_number)
	get_compression_suites(compression_suites)

	offset = parse_extension(hello_message, offset)

	print("ServerHello - Server selected %r" % get_tls_version(selected_version))

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

# Parse a Certificate message
#
def dissect_certificates_chain(hello_message):

	offset = 0

	certificate_count = 0
	certificates_len = int.from_bytes(hello_message[offset : offset + 3], 'big')
	offset += 3
	remaining_len = certificates_len

	print("certificates chain length : %r" % certificates_len)

	while remaining_len > 0:
		certificate_len = int.from_bytes(hello_message[offset : offset + 3], 'big')
		offset += 3
		remaining_len -= 3

		certificate = hello_message[offset : offset + certificate_len]
		print("certificate n°%r, %r bytes : %r" % (certificate_count, hex(certificate_len), certificate))

		offset += certificate_len
		remaining_len -= certificate_len

		certificate_count += 1

	print("read all the certificates ! ")

	return offset

# Parse a ServerKeyExchange message
#
def dissect_server_key_exchange(hello_message):

	offset = 0

	if key_exchange_algorithm == "ECDHE_RSA":
		print(key_exchange_algorithm)
	elif key_exchange_algorithm == "DHE_DSS":
		print(key_exchange_algorithm)
	elif key_exchange_algorithm == "DHE_RSA":
		print(key_exchange_algorithm)
	elif key_exchange_algorithm == "RSA":
		print(key_exchange_algorithm)
	else:
		print(key_exchange_algorithm)

	#server_key_exchange_len = int.from_bytes(hello_message[offset - 3 : offset], 'big')
	#server_key_exchange = hello_message[offset : offset + server_key_exchange_len]
	#offset += server_key_exchange_len

	#print("server_key_exchange_len length : %r" % server_key_exchange_len)
	#print("server_key_exchange : %r" % server_key_exchange)

	return offset

# Parse a ClientKeyExchange message
#
def dissect_client_key_exchange(hello_message):

	offset = 0

	if key_exchange_algorithm == "ECDHE_RSA":
		print(key_exchange_algorithm)
	elif key_exchange_algorithm == "DHE_DSS":
		print(key_exchange_algorithm)
	elif key_exchange_algorithm == "DHE_RSA":
		print(key_exchange_algorithm)
	elif key_exchange_algorithm == "RSA":
		print(key_exchange_algorithm)
	else:
		print(key_exchange_algorithm)

	client_key_exchange_len = int.from_bytes(hello_message[offset - 3 : offset], 'big')
	client_key_exchange = hello_message[offset : offset + client_key_exchange_len]
	offset += client_key_exchange_len

	print("client_key_exchange_len length : %r" % client_key_exchange_len)
	print("client_key_exchange : %r" % client_key_exchange)

	return offset

# Parse a ServerHelloDone message
#
def dissect_server_hello_done(tls_packet):
	print("server_hello_done - nothing to do")

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
	
	while offset < record_len:

		# We shall have at least 4 bytes
		# (content_type + length)
		if (record_len - offset) < 4:
			print("Error: The Handshake record is too short (%r remaining bytes)" % (record_len - offset))
			exit(0)

		(message_type, message_len) = handshake_record_get_header(handshake_record, offset)
		offset += 4

		print("  Handshake message n°%r:" % message_index)
		print("  Handshake Type %r (%r)" % (message_type, get_handshake_type(message_type)))
		print("  Message length : %r" % message_len)

		handshake_message = handshake_record[offset : offset + message_len]
		print("handshake_message %r : %r" % (message_index, handshake_message))
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
		# case 24 - KeyUpdate
		elif message_type == 24:
			dissect_key_update(handshake_message)
		# case 254 - MessageHash
		elif message_type == 254:
			dissect_message_hash(handshake_message)
		# default case - can be an encrypted handshake message
		else:
			# if the handshake message is weird and ChangeCipherSpec was seen,
			# we consider we have an encrypted handshake
			# and we skip the record
			if (is_from_client and client_finished_handshake):
			    print("Unknown handshake message (%r) from client - could be an encrypted handshake message ?" % message_type)
			    offset += (record_len - 4)
			elif server_finished_handshake:
			    print("Unknown handshake message (%r) from server - could be an encrypted handshake message ?" % message_type)
			    offset += (record_len - 4)
			# if the handshake message is weird but no ChangeCipherSpec was seen,
			# ...then the message is just weird
			else:
			    print("Unknown handshake message (%r) !" % message_type)

		# increment the record counter
		message_index += 1

# Parse an Application record
# Basically nothing to do
#
def dissect_application_record(tls_record):
	print("  Application record")


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
	check_tcpip_layer(packet, index)

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

		if (tls_packet_len - offset < record_len):
			print("TLS packet seems to be fragmented across several TCP segments...")

			previous_packet_fragmented = tls_packet
			previous_offset = offset - 5
			previous_tls_packet_index = index
			previous_record_index = record_index
			break

		tls_record = tls_packet[offset : offset + record_len]
		print(" tls_record %r : %r" % (record_index, tls_record))
		offset += record_len

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
								required=False,
								help="The file containing master secret & crypto stuffs to decrypt the traffic. This file comes from openssl s_client --keylogfile",
								type=str)

	args = parser.parse_args()

	pcap_path = args.pcap
	keylogfile = args.keylogfile

	try:
		pcap = rdpcap(pcap_path)
	except:
		print("a problem occured while opening %r" % pcap_path)
		exit(0)

	global addr_client
	global addr_server
	global is_from_client

	if pcap[0].haslayer(IP): 
		addr_client = pcap[0][IP].src
		addr_server = pcap[0][IP].dst
	elif pcap[0].haslayer(IPv6):
		addr_client = pcap[0][IPv6].src
		addr_server = pcap[0][IPv6].dst	
	else:
		print("Error: first packet doesn't have any IP layer")
		exit(0)

	# by assumption, first packet is from client to server
	is_from_client = True

	# there is no key exchange algorithm at the very begining
	key_exchange_algorithm = ""

	for i in range(len(pcap)):
		dissect_tls_packet(pcap[i], i)

if __name__ == '__main__':
	main()
