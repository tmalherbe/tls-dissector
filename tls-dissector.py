#!/usr/bin/python3.9
# -*- coding: utf-8 -*-

import argparse
import base64
import binascii

from Cryptodome.Hash import HMAC as hmac, MD5, SHA1, SHA256, SHA384
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

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

	# RSA-based cipher suites.
	#
	# Require an RSA certificate.
	# PremasterSecret is encrypted with the server public key.
	0x0001: "TLS_RSA_WITH_NULL_MD5",
	0x0002: "TLS_RSA_WITH_NULL_SHA",
	0x0004: "TLS_RSA_WITH_RC4_128_MD5",
	0x0005: "TLS_RSA_WITH_RC4_128_SHA",
	0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
	0x0007: "TLS_RSA_WITH_IDEA_CBC_SHA",
	0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
	0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x003B: "TLS_RSA_WITH_NULL_SHA256",
	0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",

	# Diffie-Hellman based cipher suites.
	#
	# Require a certificate embedding the
	# server Diffie-Hellman parameters signed by the CA.
	0x000B: "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
	0x000C: "TLS_DH_DSS_WITH_DES_CBC_SHA",
	0x000D: "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
	0x000E: "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x000F: "TLS_DH_RSA_WITH_DES_CBC_SHA",
	0x0010: "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0030: "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
	0x0031: "TLS_DH_RSA_WITH_AES_128_CBC_SHA",

	# Ephemeral Diffie-Hellman cipher suites.
	#
	# Ephemeral Diffie-Hellman server parameter
	# will be sent during ServerKeyExchange,
	# signed by the server certificate.
	0x0011: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
	0x0012: "TLS_DHE_DSS_WITH_DES_CBC_SHA",
	0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
	0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
	0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	0x0036: "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
	0x0037: "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
	0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
	0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	0x003E: "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
	0x003F: "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
	0x0040: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
	0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	0x0068: "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
	0x0069: "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
	0x006A: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
	0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",

	# Anonymous Diffie-Hellman cipher suites.
	#
	# DH parameters are sent unsigned...
	0x0017: "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
	0x0018: "TLS_DH_anon_WITH_RC4_128_MD5",
	0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
	0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
	0x003A: "TLS_DH_anon_WITH_AES_256_CBC_SHA",
	0x006C: "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
	0x006D: "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
	
	# TLSv1.3 cipher suites.
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

	# TLS CAMELLIA cipher suites - RFC 5932
	0x0041: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
	0x0042: "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
	0x0043: "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
	0x0044: "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
	0x0045: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
	0x0046: "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
	0x0084: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
	0x0085: "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
	0x0086: "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
	0x0087: "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
	0x0088: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
	0x0089: "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
	0x00BA: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	0x00BB: "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",
	0x00BC: "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	0x00BD: "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
	0x00BE: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	0x00BF: "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
	0x00C0: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
	0x00C1: "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",
	0x00C2: "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256",
	0x00C3: "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
	0x00C4: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
	0x00C5: "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256",

	# TLS SEED cipher suites - RFC 4162
	0x0096: "TLS_RSA_WITH_SEED_CBC_SHA",
	0x0097: "TLS_DH_DSS_WITH_SEED_CBC_SHA",
	0x0098: "TLS_DH_RSA_WITH_SEED_CBC_SHA",
	0x0099: "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
	0x009A: "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
	0x009B: "TLS_DH_anon_WITH_SEED_CBC_SHA",

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

def is_a_tls13_ciphersuite(cipher_suite):
	if cipher_suite > 0x1300 and cipher_suite < 0x1306:
		return True
	return False

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

def get_extension_type(extension_type):
	try:
		return extension_types[extension_type]
	except:
		print("extension %r is unknown" % hex(extension_type))

# Some global variables to handle SSL/TLS state-machine
#

debug = False

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

# global variable for the selected ciphersuite
selected_cipher_suite = 0x0000

# global variable for the selected encryption algorithm
cipher_algorithm = ""

# global variable for the selected mac algorithm
mac_algorithm = ""

# global variable for the selected encryption algorithm key len
cipher_algorithm_keylen = 0

# global variable for the selected encryption algorithm block len
cipher_algorithm_blocklen = 0

# global varaible for the selected aead algorithm salt len
cipher_algorithm_saltlen = 0

# global variable for the selected mac algorithm keylen
mac_algorithm_keylen = 0

# global variable set to True if message is client -> server
is_from_client = False

# global variable for the selected TLS version
selected_version = None

# global variable for the cryptographic material generation
client_random = None
server_random = None
master_secret = None

# global variable for the cryptographic material
key_block = None

# global variable to store the keylogfile name
keylogfile = None

# in TLSv1.0 - 1st application record uses an IV coming from key_block
# and following records use the end of the previous record as an IV.
is_first_block_cli = True
is_first_block_srv = True
last_iv_cli = None
last_iv_srv = None

# We need to know if client+server agreed on using encrypt_then_mac
# when we attempt to decrypt an application record
encrypt_then_mac = False

# Functions to compute session keys from master_secret
#

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

def get_cipher_algo_blocklen():
	global cipher_algorithm
	global cipher_algorithm_blocklen

	if cipher_algorithm == "AES_128_CBC" or cipher_algorithm == "AES_256_CBC":
		cipher_algorithm_blocklen = 16

	if cipher_algorithm == "AES_128_GCM" or cipher_algorithm == "AES_256_GCM":
		cipher_algorithm_blocklen = 16

def get_cipher_algo_saltlen():
	global cipher_algorithm
	global cipher_algorithm_saltlen

	if cipher_algorithm == "AES_128_GCM" or cipher_algorithm == "AES_256_GCM":
		cipher_algorithm_saltlen = 4

def get_mac_algo_keylen():
	global mac_algorithm
	global mac_algorithm_keylen

	if mac_algorithm == "SHA384":
		mac_algorithm_keylen = 48
	elif mac_algorithm == "SHA256":
		mac_algorithm_keylen = 32
	elif mac_algorithm == "SHA":
		mac_algorithm_keylen = 20

# Get the key exchange algorithm from the the selected CipherSuite
#
def get_key_exchange_algorithm(selected_ciphersuite):
    ciphersuite_name = cipher_suites[selected_ciphersuite]
    global key_exchange_algorithm
    key_exchange_algorithm = ciphersuite_name.split('_')[1] + "_" + ciphersuite_name.split('_')[2]
    return key_exchange_algorithm

def xor(x, y):
	if len(x) != len(y):
		print("error, x and y don't have the same length");
		exit(0)
	return bytes(a ^ b for a, b in zip(x, y))

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

def PRF(secret, label, seed):

	global debug
	if debug == True:
		print("PRF(%r, %r, %r)" % (secret, label, seed) )

	if selected_version < 0x0303:
		l = len(secret)

		S1 = secret[:l//2]
		S2 = secret[l//2:]
		p_md5 = P_MD5(S1, label + seed, 20)
		p_sha1 = P_SHA1(S2, label + seed, 16)

		return xor(p_md5, p_sha1)
	else:
		if mac_algorithm == 'SHA384':
			return P_SHA384(secret, label + seed, 20)
		else:
			return P_SHA256(secret, label + seed, 20)

def derivate_crypto_material():

	global key_block
	global debug

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

	if client_finished_handshake and server_finished_handshake:
		derivate_crypto_material()

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

    # ClientHello - we can have several supported versions
	if is_from_client == True:
		supported_versions_number = extension_content[0] >> 1

		for i in range(supported_versions_number):
			supported_version = int.from_bytes(extension_content[1 + 2*i : 1 + 2*i + 2], 'big')

			print("\t\t - supported version n°%r : %r (%r)" % (i, hex(supported_version), get_tls_version(supported_version)))

    # ServerHello - we shall have only one supported version
	else:
		supported_version_len =  extension_content[0]

		# The server supported version shall be on two bytes
		if len(extension_content) != 2:
		    print("\t\t - ? supported version returned by the server is weird (len = %r)" % supported_version_len)

		# if TLSv1.3, the content content of this extension in ServerHello
		# Overrides the version number set in the ServerHello message
		supported_version = int.from_bytes(extension_content[0:2], 'big')
		selected_version = supported_version

		print("\t\t - Server supported version : %r (%r)" % (hex(supported_version), get_tls_version(supported_version)))

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
		# supported_version extension
		if extension_type == 43:
		    dissect_extension_supported_version(extension_content)
		# encrypt_then_mac extension
		elif extension_type == 22 and is_from_client == False:
		    global encrypt_then_mac
		    encrypt_then_mac = True
		    print("\t => Server wants to use encrypt_then_mac !")

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
	
	random = hello_message[offset : offset + 32]
	client_random = random
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


# Parse a ServerHello message
#
def dissect_server_hello(hello_message):

	offset = 0
	global selected_version
	global server_random
	global selected_cipher_suite

	packet_version = int.from_bytes(hello_message[offset : offset + 2], 'big')
	selected_version = packet_version
	offset += 2

	random = hello_message[offset : offset + 32]
	server_random = random
	offset += 32

	session_id_len = hello_message[offset]
	offset += 1

	session_id = hello_message[offset : offset + session_id_len]
	offset += session_id_len

	selected_cipher_suite = int.from_bytes(hello_message[offset : offset + 2], 'big')
	get_cipher_algo()
	get_cipher_algo_keylen()
	get_cipher_algo_blocklen()
	get_cipher_algo_saltlen()

	get_mac_algo()
	get_mac_algo_keylen()

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

	if is_a_tls13_ciphersuite(selected_cipher_suite) == False:
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

# returns a base64-nicely-encoded certificate
#
def dump_b64_cert(certificate):
	b64_cert_raw = base64.b64encode(certificate)
	b64_cert = ""
	i = 0

	while i < len(b64_cert_raw):
		b64_cert_chunk = b64_cert_raw[i : i + 64]
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

	print("certificates chain length : %r" % certificates_len)

	while remaining_len > 0:
		certificate_len = int.from_bytes(hello_message[offset : offset + 3], 'big')
		offset += 3
		remaining_len -= 3

		certificate = hello_message[offset : offset + certificate_len]
		print("certificate n°%r, %r (%r) bytes : \n%s" % (certificate_count, certificate_len, hex(certificate_len), dump_b64_cert(certificate)))

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

# Parse a Finished message
#
def dissect_finished(hello_message):

	global last_iv_srv
	global is_first_block_srv

	offset = 0

	if encrypt_then_mac == False:
		if is_from_client == False:
			last_iv_srv = hello_message[-cipher_algorithm_blocklen:]
			is_first_block_srv = False
	else:
		if is_from_client == False:
			encrypted_record = hello_message[: -mac_algorithm_keylen]
			last_iv_srv = encrypted_record[-16:]
			is_first_block_srv = False

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

		if debug == True:
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
			# it's probably the Finished message.
			if (is_from_client and client_finished_handshake):
			    dissect_finished(handshake_message)
			    offset += (record_len - 4)
			elif server_finished_handshake:
			    dissect_finished(handshake_message)
			    offset += (record_len - 4)
			# if the handshake message is weird but no ChangeCipherSpec was seen,
			# ...then the message is just weird
			else:
			    print("Unknown handshake message (%r) !" % message_type)

		# increment the record counter
		message_index += 1

# TLS uses a PKCS#5 padding (\x03\x03\x03)
# prefixed with the padding length (therefore \x03\x03\x03\x03)
def unpad(padded_record):
	last_byte = padded_record[-1]

	if last_byte > cipher_algorithm_blocklen:
		print("Padding Error ! Padding is longer than the cipher block size ! (%r)" % last_byte)
		return None
	elif last_byte > 0:
		for i in range(last_byte + 1):
			#print("padded_record[%r] : %r" % ( len(padded_record) - i - 1, padded_record[-i - 1]))
			if padded_record[-i - 1] != last_byte:
				print("Padding Error ! Padding is not correct (padded_record : %r)" % padded_record)
				return None

	unpadded_record = padded_record[: - last_byte - 1]
	return unpadded_record

def decrypt_TLS1_0_record(tls_record):

	global is_first_block_cli
	global is_first_block_srv

	global last_iv_cli
	global last_iv_srv

	if debug == True and encrypt_then_mac == True:
		print("TLSv1.0 decryption - encrypt_then_mac is used")

	if is_from_client == True:
		enc_key = key_block[2 * mac_algorithm_keylen : 2 * mac_algorithm_keylen + cipher_algorithm_keylen]
		if is_first_block_cli:
			iv = key_block[2 * mac_algorithm_keylen + 2 * cipher_algorithm_keylen : 2 * mac_algorithm_keylen + 2 * cipher_algorithm_keylen + cipher_algorithm_blocklen]
			is_first_block_cli = False
		else:
			iv = last_iv_cli
	elif is_from_client == False:
		enc_key = key_block[2 * mac_algorithm_keylen + cipher_algorithm_keylen : 2 * mac_algorithm_keylen + 2 * cipher_algorithm_keylen]
		if is_first_block_srv:
			iv = key_block[2 * mac_algorithm_keylen + 2 * cipher_algorithm_keylen + cipher_algorithm_blocklen : 2 * mac_algorithm_keylen + 2 * cipher_algorithm_keylen + 2 * cipher_algorithm_blocklen]
			is_first_block_srv = False
		else:
			iv = last_iv_srv

	if debug == True:
		print("iv : %r len(iv) %r" % (iv, len(iv)))

	cipher = AES.new(enc_key, AES.MODE_CBC, iv)
	if encrypt_then_mac == False:
		try:
			decrypted_record_padded = cipher.decrypt(tls_record)
			decrypted_record = unpad(decrypted_record_padded)

			# last plaintext bytes contains the MAC
			plaintext = decrypted_record[: - mac_algorithm_keylen]
			real_mac = decrypted_record[- mac_algorithm_keylen:]

			if debug == True:
				print("  Mac : %r" % real_mac)
				print("  Decrypted data : %r" % decypted_record)
			print("  Decrypted data: %r" % plaintext)

		except ValueError:
			print("  Decryption error !")

		if is_from_client == True:
			last_iv_cli = tls_record[-16:]
		else:
			last_iv_srv = tls_record[-16:]
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

		except ValueError as e:
			print("  Decryption error ! (%r)" % e)
		if is_from_client == True:
			last_iv_cli = encrypted_record[-16:]
		else:
			last_iv_srv = encrypted_record[-16:]

def decrypt_TLS1_1_record(tls_record):

	if is_from_client == True:
		enc_key = key_block[2 * mac_algorithm_keylen : 2 * mac_algorithm_keylen + cipher_algorithm_keylen]
	elif is_from_client == False:
		enc_key = key_block[2 * mac_algorithm_keylen + cipher_algorithm_keylen : 2 * mac_algorithm_keylen + 2 * cipher_algorithm_keylen]

	iv = tls_record[:cipher_algorithm_blocklen]

	if debug == True:
		print("iv : %r len(iv) %r" % (iv, len(iv)))

	cipher = AES.new(enc_key, AES.MODE_CBC, iv)

	if encrypt_then_mac == False:
		try:
			decrypted_record_padded = cipher.decrypt(tls_record)
			decrypted_record = unpad(decrypted_record_padded)

			# last plaintext bytes contains the MAC
			plaintext = decrypted_record[cipher_algorithm_blocklen: - mac_algorithm_keylen]
			real_mac = decrypted_record[- mac_algorithm_keylen:]

			if debug == True:
				print("decrypted_record_padded : %r" % decrypted_record_padded)
				print("decrypted_record : %r" % decrypted_record)
				print("  Mac : %r" % real_mac)
			print("  Decrypted data: %r" % plaintext)

		except ValueError:
			print("  Decryption error !")
	else:
		try:
			# MAC is at the begining of the encrypted record
			real_mac = tls_record[- mac_algorithm_keylen:]
			encrypted_record = tls_record[cipher_algorithm_blocklen: -mac_algorithm_keylen]
			decrypted_record = cipher.decrypt(encrypted_record)
			plaintext = unpad(decrypted_record)

			if debug == True:
				print("  Mac : %r (%r bytes)" % (real_mac, len(real_mac)))
				print("  encrypted record with mac : %r (%r bytes)" % (encrypted_record, len(encrypted_record)))
				print("  decrypted_record : %r" % decrypted_record)
			print("  Decrypted data : %r" % plaintext)

		except ValueError as e:
			print("  Decryption error ! (%r)" % e)

def decrypt_TLS_GCM_record(tls_record):

	if is_from_client == True:
		enc_key = key_block[ : cipher_algorithm_keylen]
		salt = key_block[2 * cipher_algorithm_keylen : 2 * cipher_algorithm_keylen + cipher_algorithm_saltlen]
	elif is_from_client == False:
		enc_key = key_block[cipher_algorithm_keylen : 2 * cipher_algorithm_keylen]
		salt = key_block[2 * cipher_algorithm_keylen + cipher_algorithm_saltlen : 2 * cipher_algorithm_keylen + 2 * cipher_algorithm_saltlen]

	nonce_explicit = tls_record[ : 8]
	aead_ciphertext = tls_record[8 : ]
	nonce = salt + nonce_explicit

	additional_data =  nonce_explicit + b'\x17' + selected_version.to_bytes(2, 'big') + (len(aead_ciphertext) - cipher_algorithm_blocklen).to_bytes(2, 'big')

	if debug == True:
		print("salt : %r len(salt) %r" % (salt, len(salt)))
		print("nonce_explicit : %r" % nonce_explicit)
		print("nonce : %r" % nonce)

	cipher = AES.new(enc_key, AES.MODE_GCM, nonce)
	cipher.update(additional_data)
	plaintext = cipher.decrypt(aead_ciphertext[: - cipher_algorithm_blocklen])

	print("plaintext : %r (%r bytes)" % (plaintext, len(plaintext)))

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

	# set the keylogfile if any
	global keylogfile
	keylogfile = args.keylogfile

	# let's dissect every packet in the pcap !
	for i in range(len(pcap)):
		dissect_tls_packet(pcap[i], i)

if __name__ == '__main__':
	main()
