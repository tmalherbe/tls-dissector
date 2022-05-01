# several enums & their getters:
# - tls versions
# - records types
# - handshake messages types
# - cipher suites
# - handshake messages extensions

## tls version ##
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

## content types ##
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

## handshake messages ##
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

## cipher suites ##
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
		    print("  - " + cipher_suites[cipher_suite])
		except:
		    print("cipher_suite %r is unknown" % hex(cipher_suite))

## compression ##
def get_compression_suites(compression_suites_array):
	print("  - %r" % compression_suites_array)

## extensions ##
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

