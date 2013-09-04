#!/usr/bin/env python3

'''Test for response rcodes'''

import dnstest

t = dnstest.DnsTest()

server = t.server("knot")
zone = t.zone("example.com.")

t.link(zone, server)

t.start()

# No error.
resp = server.dig("example.com", "SOA")
resp.check(rcode="NOERROR")

# Not existent subdomain.
resp = server.dig("unknown.example.com", "SOA")
resp.check(rcode="NXDOMAIN")

# Not provided domain.
resp = server.dig("example.cz", "SOA")
resp.check(rcode="REFUSED")

t.stop()
