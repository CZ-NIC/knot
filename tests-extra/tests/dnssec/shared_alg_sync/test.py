#!/usr/bin/env python3

"""
Test shared KSK and algorithm change.
"""

from dnstest.utils import *
from dnstest.test import Test

def check_zone(server, zone, soa_rrsigs, msg):
    qsoa = server.dig(zone.name, "SOA", dnssec=True, bufsize=4096)
    found_soa_rrsigs = qsoa.count("RRSIG")
    if found_soa_rrsigs != soa_rrsigs:
        set_err("BAD RRSIG COUNT: " + msg)
        detail_log("!RRSIGs not published and activated as expected: " + msg)

t = Test()

knot = t.server("knot")
zones = t.zone_rnd(2, dnssec=False, records=10)
t.link(zones, knot)
z0name = zones[0].name

for z in zones:
    knot.dnssec(z).enable = (z.name == z0name)
    knot.dnssec(z).ksk_shared = True
    knot.dnssec(z).alg = "ECDSAP256SHA256"
    knot.dnssec(z).shared_policy_with = zones[0].name

t.start()
knot.zones_wait(zones)

for z in zones:
    check_zone(knot, z, 1 if z.name == z0name else 0, "initial sign")
    knot.dnssec(z).disable = knot.dnssec(z).enable
    knot.dnssec(z).enable = True
    knot.dnssec(z).alg = "ECDSAP384SHA384"

knot.gen_confile()
knot.reload()
t.sleep(4)

check_zone(knot, zones[1], 1, "after sharing")

t.end()
