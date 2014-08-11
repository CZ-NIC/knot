#!/usr/bin/env python3

'''Test for EDNS version'''

from dnstest.test import Test

t = Test()

server = t.server("knot")
zone = t.zone("example.com.")

t.link(zone, server)

t.start()

# Supported EDNS version 0.
resp = server.dig("example.com", "SOA", edns=0)
resp.check(rcode="NOERROR")

# Unsupported EDNS version 1.
resp = server.dig("example.com", "SOA", edns=1)
resp.check(rcode="BADVERS")

t.end()
