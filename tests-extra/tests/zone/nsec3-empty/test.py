#!/usr/bin/env python3

'''Test no NSEC3 records handling. '''

from dnstest.test import Test

t = Test()

master = t.server("knot")

# Zone setup
zones = t.zone("example.com.", storage=".") + t.zone("evil.test.", storage=".")

t.link(zones, master)

master.conf_zone(zones[1]).semantic_checks = False

t.start()

# Load zone
master.zones_wait(zones)

# Query non-existent names
resp = master.dig("bogus.example.com", "A", dnssec=True)
resp.check(rcode="NXDOMAIN")
resp = master.dig("nx.evil.test", "A", dnssec=True)
resp.check(rcode="NXDOMAIN")

t.end()
