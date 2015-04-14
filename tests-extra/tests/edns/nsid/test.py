#!/usr/bin/env python3

'''Test for EDNS0/NSID identification'''

from dnstest.test import Test

t = Test()

name = "Knot DNS server"
hex_name = "0x01020304"
server1 = t.server("knot", nsid=name)
server2 = t.server("knot", nsid=False)
server3 = t.server("knot")
server4 = t.server("knot", nsid=hex_name)
zone = t.zone("example.com.")

t.link(zone, server1)
t.link(zone, server2)
t.link(zone, server3)
t.link(zone, server4)

t.start()

# 1) Custom identification string.
resp = server1.dig("example.com", "SOA", nsid=True)
resp.check_edns(nsid=name)

# 2) Disabled.
resp = server2.dig("example.com", "SOA", nsid=True)
resp.check_edns()

# 3) FQDN hostname.
resp = server3.dig("example.com", "SOA", nsid=True)
resp.check_edns(nsid=t.hostname)

# 4) Hex string.
resp = server4.dig("example.com", "SOA", nsid=True)
resp.check_edns(nsid=hex_name)

t.end()
