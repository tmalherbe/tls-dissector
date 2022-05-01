## is debug activated ? ##
debug = False

## client & server addresses ##
addr_client = ""
addr_server = ""

## does this packet come from client ? ##
is_from_client = False

# global variables to store piece of a TLS packet
# in case this packet is fragmented into several
# TCP packets
#
previous_packet_fragmented = None
previous_offset = 0
previous_tls_packet_index = 0
previous_record_index = 0

