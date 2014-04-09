#!/usr/bin/env python3

'''Test for mismatched TTLs handling on slave zone load.'''

'''NOTE: dnspython can't keep different TTLs in one rrset. So we can't check
         the slave server properly.'''

from dnstest.test import Test

t = Test()

master = t.server("dummy")
slave = t.server("knot")

zone = t.zone("ttl-mismatch.", storage=".", exists=False)

t.link(zone, master, slave)

# Create invalid zone file.
slave.update_zonefile(zone, version=1)

t.start()

# Check if the zone was loaded.
resp = slave.dig("ttl.ttl-mismatch.", "A")
resp.check(rcode="NOERROR", flags="QR AA", noflags="TC AD RA")

t.end()
