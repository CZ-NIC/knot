#!/usr/bin/env python3

'''Test no NSEC3 records handling. '''

from dnstest.test import Test

t = Test()

master = t.server("knot")

# Zone setup
zone = t.zone("example.com.", storage=".")

t.link(zone, master)

t.start()

# Load zone
master.zone_wait(zone)

# Query non-existent name
resp = master.dig("bogus.example.com", "A", dnssec=True)
resp.check(rcode="NXDOMAIN")

t.end()
