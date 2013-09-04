#!/usr/bin/env python3

'''Test for EDNS0/NSID identification'''

import dnstest
import socket

t = dnstest.DnsTest()

name = "Knot DNS server"
hex_name = "0x01020304"
server1 = t.server("knot", nsid=name)
server2 = t.server("knot", nsid=True)
server3 = t.server("knot", nsid=False)
server4 = t.server("knot")
server5 = t.server("knot", nsid=hex_name)
zone = t.zone("example.com.")

t.link(zone, server1)
t.link(zone, server2)
t.link(zone, server3)
t.link(zone, server4)
t.link(zone, server5)

t.start()

# 1) Custom identification string.
resp = server1.dig("example.com", "SOA", nsid=True)
resp.check_edns(nsid=name)

# 2) FQDN hostname.
resp = server2.dig("example.com", "SOA", nsid=True)
resp.check_edns(nsid=socket.getfqdn())

# 3) Explicitly disabled.
resp = server3.dig("example.com", "SOA", nsid=True)
resp.check_edns()

# 4) Disabled.
resp = server4.dig("example.com", "SOA", nsid=True)
resp.check_edns()

# 5) Hex string.
resp = server5.dig("example.com", "SOA", nsid=True)
resp.check_edns(nsid=hex_name)

t.stop()
