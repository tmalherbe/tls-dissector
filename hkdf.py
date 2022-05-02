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

def HKDF_Extract(salt, IKM):
	h = hmac.new(salt, digestmod = SHA384)#SHA256)
	h.update(IKM)
	PRK = h.digest()
	print("PRK : %r" % binascii.hexlify(PRK))
	return PRK

def HKDF_Expand(PRK, info, L):
	T = []
	T0 = b''
	T.append(T0)
	
	n = 1 + L // 32
	#print(n)
	
	for i in range(n):
		h = hmac.new(PRK, digestmod = SHA384)#SHA256)
		h.update(T[i] + info + (i+1).to_bytes(1, 'big'))
		T_i_plus = h.digest()
		T.append(T_i_plus)
	OKM = b''
	for i in range(len(T)):
		OKM += T[i]
	return OKM[:L]


def HKDF_Expand_big(salt, info, IKM, L):
	PRK = HKDF_Extract(salt, IKM)
	
	return HKDF_Expand(PRK, info, L)

print("test 1")
IKM = b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
salt = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c'
info = b'\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9'
L = 42
OKM = HKDF_Expand_big(salt, info, IKM, L)
print("OKM : %r" % binascii.hexlify(OKM))

print("test 2")
IKM = b''
salt = b''
info = b''
for i in range(80):
	IKM += i.to_bytes(1, 'big')
	salt += (i + 0x60).to_bytes(1, 'big')
	info += (i + 0xb0).to_bytes(1, 'big')
print("IKM : %r" % binascii.hexlify(IKM))
print("salt : %r" % binascii.hexlify(salt))
print("info : %r" % binascii.hexlify(info))
L = 82
OKM = HKDF_Expand_big(salt, info, IKM, L)
print("OKM : %r" % binascii.hexlify(OKM))

print("test 3")
IKM = b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
salt = b''
info = b''
L = 42
OKM = HKDF_Expand_big(salt, info, IKM, L)
print("OKM : %r" % binascii.hexlify(OKM))

client_hello = b'\x01\x00\x00\xc0\x03\x03\xcb\x34\xec\xb1\xe7\x81\x63\xba\x1c\x38\xc6\xda\xcb\x19\x6a\x6d\xff\xa2\x1a\x8d\x99\x12\xec\x18\xa2\xef\x62\x83\x02\x4d\xec\xe7\x00\x00\x06\x13\x01\x13\x03\x13\x02\x01\x00\x00\x91\x00\x00\x00\x0b\x00\x09\x00\x00\x06\x73\x65\x72\x76\x65\x72\xff\x01\x00\x01\x00\x00\x0a\x00\x14\x00\x12\x00\x1d\x00\x17\x00\x18\x00\x19\x01\x00\x01\x01\x01\x02\x01\x03\x01\x04\x00\x23\x00\x00\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20\x99\x38\x1d\xe5\x60\xe4\xbd\x43\xd2\x3d\x8e\x43\x5a\x7d\xba\xfe\xb3\xc0\x6e\x51\xc1\x3c\xae\x4d\x54\x13\x69\x1e\x52\x9a\xaf\x2c\x00\x2b\x00\x03\x02\x03\x04\x00\x0d\x00\x20\x00\x1e\x04\x03\x05\x03\x06\x03\x02\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x01\x04\x02\x05\x02\x06\x02\x02\x02\x00\x2d\x00\x02\x01\x01\x00\x1c\x00\x02\x40\x01'
server_hello = b'\x02\x00\x00\x56\x03\x03\xa6\xaf\x06\xa4\x12\x18\x60\xdc\x5e\x6e\x60\x24\x9c\xd3\x4c\x95\x93\x0c\x8a\xc5\xcb\x14\x34\xda\xc1\x55\x77\x2e\xd3\xe2\x69\x28\x00\x13\x01\x00\x00\x2e\x00\x33\x00\x24\x00\x1d\x00\x20\xc9\x82\x88\x76\x11\x20\x95\xfe\x66\x76\x2b\xdb\xf7\xc6\x72\xe1\x56\xd6\xcc\x25\x3b\x83\x3d\xf1\xdd\x69\xb1\xb0\x4e\x75\x1f\x0f\x00\x2b\x00\x02\x03\x04'

h = SHA256.new()
h.update(client_hello)
h.update(server_hello)
print("transcript-hash : %r" % h.hexdigest())

def HKDF_Expand_Label(secret, label, context, L):
	tmpLabel = b'tls13 ' + label
	HkdfLabel = L.to_bytes(2, 'big') + (len(tmpLabel)).to_bytes(1, 'big') + tmpLabel + context
	print("HkdfLabel : %r" % binascii.hexlify(HkdfLabel))

	return HKDF_Expand(secret, HkdfLabel, L)

####################################################################################################################################

print("")

SERVER_HANDSHAKE_TRAFFIC_SECRET = b'\x24\x8D\xB6\x35\x31\xA8\x27\x7F\x13\x0B\x9A\xF0\xA6\xC9\x10\xBF\x83\x54\xE5\xD5\xDA\x8E\xBB\x60\x52\x6B\x2E\xA8\x18\xA1\xD3\xB8\xC7\xE1\x6E\x19\x3A\xB2\x7F\x34\x57\xA3\x9E\xEC\xBA\xF7\x41\xA5'

#SERVER_HANDSHAKE_TRAFFIC_SECRET = b'\xAA\x5C\x26\x6B\x7B\x4C\x40\xA9\xE0\xE6\x9F\xEC\x26\x36\x88\x6E\x21\xD5\x43\x7D\x13\x26\x17\x14\x40\xC7\xA8\xD1\x8E\x44\x62\xD7\x4E\x9F\x64\x5F\xDA\x57\x43\x92\xAB\x7A\x6C\x8E\x28\x04\x82\xBE'

salt = SERVER_HANDSHAKE_TRAFFIC_SECRET
label = b'key'
L = 32
server_key = HKDF_Expand_Label(salt, label, b'\x00', L)
print("server_key : %r" % binascii.hexlify(server_key))
print("")

salt = SERVER_HANDSHAKE_TRAFFIC_SECRET
label = b'iv'
L = 12
server_key = HKDF_Expand_Label(salt, label, b'\x00', L)
print("iv : %r" % binascii.hexlify(server_key))
print("")
exit(0)
####################################################################################################################################

# cf https://datatracker.ietf.org/doc/html/rfc8448
print("test from rfc 8448")
salt = b'\xb6\x7b\x7d\x69\x0c\xc1\x6c\x4e\x75\xe5\x42\x13\xcb\x2d\x37\xb4\xe9\xc9\x12\xbc\xde\xd9\x10\x5d\x42\xbe\xfd\x59\xd3\x91\xad\x38'
label = b'key'
L = 16
server_key = HKDF_Expand_Label(salt, label, b'\x00', L)
print("server key : %r" % binascii.hexlify(server_key))
print("")

label = b'iv'
L = 12
server_key = HKDF_Expand_Label(salt, label, b'\x00', L)
print("server iv : %r" % binascii.hexlify(server_key))
print("")

# server_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
# avec Secret = SERVER_HANDSHAKE_TRAFFIC_SECRET
# et
# HKDF-Expand-Label(Secret, Label, Context, Length) =
# 	HKDF-Expand(Secret, HkdfLabel, Length)
# et
# HkdfLabel = length.to_bytes(2, 'big') + "tls13 " + Label + Context
