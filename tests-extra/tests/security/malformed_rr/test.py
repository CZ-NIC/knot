#!/usr/bin/env python3

'''Test checking some malformed RRtypes handling.'''

import socket
from dnstest.test import Test

t = Test()
knot = t.server("knot")
zones = t.zone("cds.empty.", storage=".") + t.zone("cds.short.", storage=".") + t.zone("nsec3.short.", storage=".")
t.link(zones, knot)

knot.conf_zone(zones).semantic_checks = True

t.start()

t.sleep(5)

for z in zones:
    resp = knot.dig(z.name, "CDS", dnssec=True)
    resp.check(rcode="SERVFAIL")

t.end()
