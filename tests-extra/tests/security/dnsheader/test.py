#!/usr/bin/env python3

'''DNS packet header parsing tests.'''

import socket
from dnstest.test import Test

t = Test(stress=False)
knot = t.server("knot")
zone = t.zone("example.com.")
t.link(zone, knot)

t.start()
knot.zone_wait(zone)

# Packet lengths shorter than DNS header
data = '\x00'
max_len = (12 + 5) # Header + minimal question size
udp_socket = knot.create_sock(socket.SOCK_DGRAM)
for i in range(1, max_len):
    knot.send_raw(data * i, udp_socket)
udp_socket.close()

# Check if the server is still alive
resp = knot.dig("example.com", "SOA")
resp.check(rcode="NOERROR")

t.end()
