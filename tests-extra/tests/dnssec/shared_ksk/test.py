#!/usr/bin/env python3
"""
Test shared KSK among zones.
"""
from dnstest.utils import *
from dnstest.test import Test

def query_ksk(server, zone): # returns KSK hash
    resp = server.dig(zone.name, "DNSKEY")
    resp.check(rcode="NOERROR")
    for rr in resp.resp.answer[0].to_rdataset():
        fields = rr.to_text().split()
        if fields[0] == "257":
            return fields[3]
    return "error"

t = Test()

knot = t.server("knot")
zones = t.zone_rnd(5, dnssec=False, records=10)
t.link(zones, knot)

for z in zones:
    knot.dnssec(z).enable = True
    knot.dnssec(z).ksk_shared = True
    knot.dnssec(z).shared_policy_with = zones[0].name

t.start()
knot.zones_wait(zones)
knot.flush(wait=True)

shared_ksk = query_ksk(knot, zones[1])

for z in zones:
    z_ksk = query_ksk(knot, z)
    if z_ksk != shared_ksk:
        set_err("KSK NOT SHARED (%s versus %s)" % (z.name, zones[1].name))

    knot.zone_verify(z)

t.end()
