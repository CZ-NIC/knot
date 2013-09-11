#!/usr/bin/env python3

'''Test for response rcodes'''

import dnstest

t = dnstest.DnsTest()

knot = t.server("knot")
bind = t.server("bind")
zone = t.zone("example.com.")

t.link(zone, knot)
t.link(zone, bind)

t.start()

# No error.
resp = knot.dig("example.com", "SOA")
resp.check(rcode="NOERROR")
resp.cmp(bind)

# Not existent subdomain.
resp = knot.dig("unknown.example.com", "SOA")
resp.check(rcode="NXDOMAIN")
resp.cmp(bind)

# Not provided domain.
resp = knot.dig("example.cz", "SOA")
resp.check(rcode="REFUSED")
resp.cmp(bind)

t.stop()
