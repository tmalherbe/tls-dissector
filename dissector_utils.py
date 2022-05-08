from scapy.all import *
#from dissector_globals import *
import dissector_globals

def get_packet_direction():
	if dissector_globals.is_from_client == True:
		print(" client -> server")
	else:
		print(" server -> client")

# Check IP/TCP layer:
# - IP4/IPv6 layer is mandatory
# - TCP/UDP layer is mandatory
# - Packet shall either be from client to server or from server to client
#
def check_tcpip_layer(packet, index, tcp):

	from dissector_globals import addr_client, addr_server

	# decide if the packet is from client or from server
	if packet.haslayer(IP):
		if packet[IP].src == addr_client and packet[IP].dst == addr_server:
			print("%r -> %r" %(addr_client, addr_server) )
			dissector_globals.is_from_client = True
		elif packet[IP].dst == addr_client and packet[IP].src == addr_server:
			print("%r -> %r" %(addr_server, addr_client) )
			dissector_globals.is_from_client = False
		else:
			print("Error: packet %r doesn't belong to the TLS stream" % index)
			exit(0)
	elif packet.haslayer(IPv6):
		if packet[IPv6].src == addr_client and packet[IPv6].dst == addr_server:
			print("%r -> %r" %(addr_client, addr_server) )
			dissector_globals.is_from_client = True
		elif packet[IPv6].dst == addr_client and packet[IPv6].src == addr_server:
			print("%r -> %r" %(addr_server, addr_client) )
			dissector_globals.is_from_client = False
		else:
			print("Error: packet %r doesn't belong to the TLS stream" % index)
			exit(0)
	else:
		print("Error: packet %r doesn't have any IP layer" % index)
		exit(0)

	# we shall have a TCP/UDP layer !
	if tcp == True:
		if not packet.haslayer(TCP):
			print("Error: packet %r doesn't have any TCP layer" % index)
			exit(0)
	else:
		if not packet.haslayer(UDP):
			print("Error: packet %r doesn't have any UDP layer" % index)
			exit(0)

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
	
# Parse the header of an handshake message
# This header shall contain:
# - 1 byte indicating the message type
# - 3 bytes indicating the message length
#
def handshake_record_get_header(handshake_record, offset):
	record_type = int.from_bytes(handshake_record[offset : offset + 1], 'big')
	record_len = int.from_bytes(handshake_record[offset + 1 : offset + 4], 'big')
	return (record_type, record_len)
