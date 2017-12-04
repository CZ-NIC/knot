#!/usr/bin/env python3

'''Test for loading of zone containing mismatched TTLs in RRSet'''

from dnstest.test import Test

t = Test()

master = t.server("knot")
zone = t.zone("ttl-mismatch", storage=".")

t.link(zone, master)

t.start()

master.zones_wait(zone)

resp = master.dig("ttl.ttl-mismatch.", "A")
resp.check(rcode="NOERROR", flags="QR AA", noflags="TC AD RA", ttl=7200)

t.end()
