#!/usr/bin/env python3

'''Test for loading of zone containing mismatched TTLs'''

from dnstest.test import Test

t = Test()

master = t.server("knot")

zone = t.zone("ttl-mismatch", storage=".")

t.link(zone, master)

t.start()

# Just check if the zone was loaded. It should be refused on master.
resp = master.dig(zone, "SOA")
resp.check(rcode="REFUSED", flags="QR", noflags="AA TC AD RA")

t.end()
