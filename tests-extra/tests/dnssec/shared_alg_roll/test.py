#!/usr/bin/env python3

"""
Test shared KSK and algorithm rollover.
"""

from dnstest.utils import *
from dnstest.test import Test

def query_ksk(server, zone, expect_alg): # returns KSK data
    resp = server.dig(zone.name, "DNSKEY")
    resp.check(rcode="NOERROR")
    for rr in resp.resp.answer[0].to_rdataset():
        fields = rr.to_text().split()
        if fields[2] != str(expect_alg):
            set_err("unexpected algorithm %s != %d" % (fields[2], expect_alg))
        if fields[0] == "257":
            return fields[3]
    return "error"

def check_rrsig_counts(server, zones, rrtype, expect_count):
    for z in zones:
        qdnskeyrrsig = server.dig(z.name, rrtype, dnssec=True, bufsize=4096)
        found_rrsigs = qdnskeyrrsig.count("RRSIG")
        if found_rrsigs != expect_count:
            return False
    return True

def wait_for_rrsig_count(t, server, zones, rrtype, rrsig_count, min_time, timeout, msg):
    rtime = 0
    while not check_rrsig_counts(server, zones, rrtype, rrsig_count):
        rtime = rtime + 1
        t.sleep(1)
        if rtime > timeout:
            break

t = Test()

knot = t.server("knot")
zones = t.zone_rnd(5, dnssec=False, records=10, ttl=3)
t.link(zones, knot)

for z in zones:
    knot.dnssec(z).enable = True
    knot.dnssec(z).ksk_shared = True
    knot.dnssec(z).alg = "ECDSAP256SHA256"
    knot.dnssec(z).shared_policy_with = zones[0].name

t.start()
knot.zones_wait(zones)
knot.flush(wait=True)

shared_ksk = query_ksk(knot, zones[1], 13)

for z in zones:
    z_ksk = query_ksk(knot, z, 13)
    if z_ksk != shared_ksk:
        set_err("KSK NOT SHARED (%s versus %s)" % (z.name, zones[1].name))

    knot.zone_verify(z)

# perform algorithm rollover
for z in zones:
    knot.dnssec(z).alg = "ECDSAP384SHA384"
    knot.dnssec(z).ksk_sbm_timeout = 10
    knot.dnssec(z).propagation_delay = 5

knot.gen_confile()
knot.reload()

wait_for_rrsig_count(t, knot, zones, "SOA", 2, 0, 20, "algorithm roll start")
wait_for_rrsig_count(t, knot, zones, "SOA", 1, 0, 80, "algorithm roll finish")
knot.flush(wait=True)

shared_ksk = query_ksk(knot, zones[1], 14)

for z in zones:
    z_ksk = query_ksk(knot, z, 14)
    if z_ksk != shared_ksk:
        set_err("KSK NOT SHARED (%s versus %s)" % (z.name, zones[1].name))

    knot.zone_verify(z)

# add newly configured zone
zones_add = t.zone_rnd(1, dnssec=False, records=10, ttl=4)
t.link(zones_add, knot)

for z in zones_add:
    knot.dnssec(z).enable = True
    knot.dnssec(z).ksk_shared = True
    knot.dnssec(z).alg = "ECDSAP384SHA384"
    knot.dnssec(z).ksk_sbm_timeout = 10
    knot.dnssec(z).propagation_delay = 5
    knot.dnssec(z).shared_policy_with = zones[0].name

knot.gen_confile()
knot.reload()
knot.zones_wait(zones_add)
knot.flush(wait=True)

shared_ksk = query_ksk(knot, zones[1], 14)

for z in zones_add:
    z_ksk = query_ksk(knot, z, 14)
    if z_ksk != shared_ksk:
        set_err("KSK NOT SHARED (%s versus %s)" % (z.name, zones[1].name))

    knot.zone_verify(z)

t.end()
