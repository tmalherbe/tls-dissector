#!/usr/bin/python3.9
# -*- coding: utf-8 -*-

import argparse

from scapy.all import *

tls_versions = {
	0x0301: "TLSv1.0",
	0x0302: "TLSv1.1",
	0x0303: "TLSv1.2",
	0x0304: "TLSv1.3"
}

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

def get_tls_version(tls_version):
	return tls_versions[tls_version]

def get_handshake_type(handshake_type):
	return handshake_types[handshake_type]

def get_extension_type(extension_type):
	try:
		return extension_types[extension_type]
	except:
		print("extension %r is unknown" % hex(extension_type))

#def tls_packet_get_header(tls_packet, offset):
#	packet_version = int.from_bytes(tls_packet[1 : 1 + 2], 'big')
#	packet_len = int.from_bytes(tls_packet[3 : 3 + 2], 'big')

def tls_packet_get_header(tls_packet, offset):
	packet_version = int.from_bytes(tls_packet[offset : offset + 2], 'big')
	packet_len = int.from_bytes(tls_packet[offset + 2 : offset + 4], 'big')

	return (packet_version, packet_len)

def dissect_ccs_packet(tls_packet, index, offset, packet_len):
	print("packet %r : change_cipher_spec" % index)
	print("i can read %r %r" % (tls_packet[offset], tls_packet[offset+1]))
	
	offset += 1
	
	return offset

def dissect_alert_packet(tls_packet, index, packet_len):
	print("packet %r : alert" % index)

def parse_extension(tls_packet, offset):
	extension_total_len = int.from_bytes(tls_packet[offset : offset + 2], 'big')
	offset += 2
	
	print("extension total length : %r" % extension_total_len)

	remaining_len = extension_total_len
	
	while remaining_len > 0:
		extension_type = int.from_bytes(tls_packet[offset : offset + 2], 'big')
		remaining_len -= 2
		offset += 2
		
		extension_len = int.from_bytes(tls_packet[offset : offset + 2], 'big')
		remaining_len -= 2
		offset += 2
		
		extension_content = tls_packet[offset : offset + extension_len]
		
		offset += extension_len
		remaining_len -= extension_len
		
		print("\t - extension type : %r (%r)" % (extension_type, get_extension_type(extension_type)))
		print("\t - extension length : %r" % extension_len)
		print("\t - extension content : %r" % extension_content)
		
	return offset

def dissect_client_hello(tls_packet, index, offset):

	packet_version = int.from_bytes(tls_packet[offset : offset + 2], 'big')
	offset += 2
	
	random = tls_packet[offset : offset + 32]
	offset += 32
	
	session_id_len = tls_packet[offset]
	offset += 1

	session_id = tls_packet[offset : offset + session_id_len]
	offset += session_id_len
	
	cipher_suite_number = int.from_bytes(tls_packet[offset : offset + 2], 'big') >> 1
	offset += 2

	cipher_suites = []
	for i in range(cipher_suite_number):
		cipher_suite = int.from_bytes(tls_packet[offset : offset + 2], 'big')
		cipher_suites.append(cipher_suite)
		offset += 2

	compression_suite_number = tls_packet[offset]
	offset += 1

	compression_suites = []
	for i in range(compression_suite_number):
		compression_suite = tls_packet[offset]
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

	offset = parse_extension(tls_packet, offset)
	return offset

def dissect_server_hello(tls_packet, index, offset):

	packet_version = int.from_bytes(tls_packet[offset : offset + 2], 'big')
	offset += 2
	
	random = tls_packet[offset : offset + 32]
	offset += 32
	
	session_id_len = tls_packet[offset]
	offset += 1

	session_id = tls_packet[offset : offset + session_id_len]
	offset += session_id_len
	
	cipher_suite = int.from_bytes(tls_packet[offset : offset + 2], 'big')
	offset += 2

	compression_suite_number = tls_packet[offset]
	offset += 1

	compression_suites = []
	for i in range(compression_suite_number):
		compression_suite = tls_packet[offset]
		compression_suites.append(compression_suite)
		offset += 1
	
	print("ServerHello - TLS version : %r (%r)" % (hex(packet_version),  get_tls_version(packet_version)))
	print("ServerHello - Random : %r" % random)
	
	if session_id_len > 0:
		print("ServerHello - SessionID : %r" % session_id)
	else:
		print("ServerHello - no SessionID")
	
	print("ServerHello - Selected CipherSuite : %r" % cipher_suites[cipher_suite])

	print("ClientHello : %r CompressionSuites :" % compression_suite_number)
	get_compression_suites(compression_suites)

	offset = parse_extension(tls_packet, offset)
	return offset

def dissect_certificate(tls_packet, index, offset):
	
	certificate_count = 0
	certificates_len = int.from_bytes(tls_packet[offset : offset + 3], 'big')
	offset += 3
	remaining_len = certificates_len
	
	print("certificates chain length : %r" % certificates_len)

	while remaining_len > 0:
		certificate_len = int.from_bytes(tls_packet[offset : offset + 3], 'big')
		offset += 3
		remaining_len -= 3
		
		certificate = tls_packet[offset : offset + certificate_len]
		print("certificate n°%r, %r bytes : %r" % (certificate_count, hex(certificate_len), certificate))
		
		offset += certificate_len
		remaining_len -= certificate_len	
		
		certificate_count += 1

	print("read all the certificates ! ")

	return offset

def dissect_server_key_exchange(tls_packet, index, offset):
	
	server_key_exchange_len = int.from_bytes(tls_packet[offset - 3 : offset], 'big')
	server_key_exchange = tls_packet[offset : offset + server_key_exchange_len]
	offset += server_key_exchange_len
	
	print("server_key_exchange_len length : %r" % server_key_exchange_len)
	print("server_key_exchange : %r" % server_key_exchange)

	return offset

def dissect_client_key_exchange(tls_packet, index, offset):

	client_key_exchange_len = int.from_bytes(tls_packet[offset - 3 : offset], 'big')
	client_key_exchange = tls_packet[offset : offset + client_key_exchange_len]
	offset += client_key_exchange_len
	
	print("client_key_exchange_len length : %r" % client_key_exchange_len)
	print("client_key_exchange : %r" % client_key_exchange)

	return offset

def dissect_server_hello_done(tls_packet, index, offset):
	print("server_hello_done - nothing to do")
	return offset

def dissect_handshake_by_type(tls_packet, index, handshake_type, offset, packet_len):
	if handshake_type == 1:
		return dissect_client_hello(tls_packet, index, offset)
	elif handshake_type == 2:
		return dissect_server_hello(tls_packet, index, offset)
	elif handshake_type == 11:
		return dissect_certificate(tls_packet, index, offset)
	elif handshake_type == 12:
		return dissect_server_key_exchange(tls_packet, index, offset)
	elif handshake_type == 14:
		return dissect_server_hello_done(tls_packet, index, offset)
	elif handshake_type == 16:
		return dissect_client_key_exchange(tls_packet, index, offset)
	else:
		print("This handshake message (%r) is not supported yet" % handshake_type)
		return -1

def dissect_handshake_packet(tls_packet, index, offset, packet_len):
	print("packet %r : handshake" % index)
	print("yyyy offset=%r packet_len=%r" % (offset, packet_len))
	while offset < packet_len + 4:
		handshake_type = tls_packet[offset]
		offset += 1
	
		hanshake_len = int.from_bytes(tls_packet[offset : offset + 3], 'big')
		offset += 3
	
		print("hanshake type : %r (%r)" % (handshake_type, get_handshake_type(handshake_type)))
		print("hanshake message length : %r" % hanshake_len)

		offset = dissect_handshake_by_type(tls_packet, index, handshake_type, offset, packet_len)
		print("sdlkdslkfj : offset %r " % offset)
		
		if offset < 0:
			print("chelou")
			exit()
		
	print("onskas")
	return offset

def dissect_data_packet(tls_packet, index):
	print("packet %r : application data" % index)

def dissect_tls_packet(packet, index):

	if packet.haslayer(IP):
		if packet[IP].src == addr_client and packet[IP].dst == addr_server:
			print("client -> server")		
		elif packet[IP].dst == addr_client and packet[IP].src == addr_server:
			print("server -> client")
		else:
			print("Error: packet %r doesn't belong to the TLS stream" % index)
			exit(0)
	elif packet.haslayer(IPv6):
		if packet[IPv6].src == addr_client and packet[IPv6].dst == addr_server:
			print("client -> server")		
		elif packet[IPv6].dst == addr_client and packet[IPv6].src == addr_server:
			print("server -> client")
		else:
			print("Error: packet %r doesn't belong to the TLS stream" % index)
			exit(0)
	else:
		print("Error: packet %r doesn't have any IP layer" % index)
		exit(0)

	if not packet.haslayer(TCP):
		print("Error: packet %r doesn't have any UDP layer" % index)
		exit(0)

	tls_packet = bytes(packet[TCP].payload)

	offset = 0

	while offset < len(tls_packet):
	
		tls_content_type = tls_packet[offset]
		print("fff tls_content_type %r" % hex(tls_content_type))
		offset += 1

		(packet_version, packet_len) = tls_packet_get_header(tls_packet, offset)
		offset += 4
	
		#print("packet version : %r" % get_tls_version(packet_version))
		print("packet version : %r" % hex(packet_version))
		print("packet length : %r" % packet_len)
	
		if tls_content_type == 20:
			offset = dissect_ccs_packet(tls_packet, index, offset, packet_len)
		elif tls_content_type == 21:
			dissect_alert_packet(tls_packet, index, offset, packet_len)
		elif tls_content_type == 22:
			offset = dissect_handshake_packet(tls_packet, index, offset, packet_len)
			print("hopla %r %r" %(packet_len, offset))
		elif tls_content_type == 23:
			dissect_data_packet(tls_packet, index, offset, packet_len)
		else:
			print("packet %r : unknown type (%r)" % (index, hex(tls_content_type)))
			#print("packet %r,  unknown type (%r), 
	print("prout, offset : %r" % offset)

	print("");

def main():

	global addr_client
	global addr_server

	parser = argparse.ArgumentParser()

	parser.add_argument("-p", "--pcap",
								required=True,
								help="TLS traffic to dissect.The pcap file. This pcap is supposed to contain only 1 TLS/TCP stream, and the 1st frame shall be the emitted by the client",
								type=str)

	args = parser.parse_args()

	pcap_path = args.pcap

	pcap = rdpcap(pcap_path)

	if pcap[0].haslayer(IP): 
		addr_client = pcap[0][IP].src
		addr_server = pcap[0][IP].dst
	elif pcap[0].haslayer(IPv6):
		addr_client = pcap[0][IPv6].src
		addr_server = pcap[0][IPv6].dst	
	else:
		print("Error: first packet doesn't have any IP layer")
		exit(0)

	for i in range(len(pcap)):
		dissect_tls_packet(pcap[i], i)

if __name__ == '__main__':
	main()
