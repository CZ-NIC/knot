#!/usr/bin/env python3

'''Test for mismatched TTLs handling on slave zone load.'''

from dnstest.test import Test

t = Test()

master = t.server("dummy")
slave = t.server("knot")

zone = t.zone("ttl-mismatch.", storage=".")

t.link(zone, master, slave)

# Create invalid zone file.
slave.update_zonefile(zone, version=1)

t.start()

t.sleep(1)

t.end()
