#!/usr/bin/env python3
"""
Test shared KSK among zones.
"""
from dnstest.utils import *
from dnstest.test import Test

def add_shared(test, server, zones, refzone):
    test.link(zones, server)
    for z in zones:
        server.dnssec(z).enable = True
        knot.dnssec(z).ksk_shared = True
        knot.dnssec(z).shared_policy_with = refzone.name

def query_ksk(server, zone): # returns KSK hash
    resp = server.dig(zone.name, "DNSKEY")
    resp.check(rcode="NOERROR")
    resp.check_count(2, rtype="DNSKEY")
    for rr in resp.resp.answer[0].to_rdataset():
        fields = rr.to_text().split()
        if fields[0] == "257":
            return fields[3]
    return "error"

def check_ksks(server, zones, refzone):
    server.zones_wait(zones)
    server.flush(wait=True)

    shared_ksk = query_ksk(server, refzone)

    for z in zones:
        z_ksk = query_ksk(server, z)
        if z_ksk != shared_ksk:
            set_err("KSK NOT SHARED (%s versus %s)" % (z.name, refzone.name))
            detail_log("KSK NOT SHARED (%s versus %s)" % (z.name, refzone.name))

        knot.zone_verify(z)

t = Test()
knot = t.server("knot")

# testcase 1: shared policy

zones0 = t.zone_rnd(5, dnssec=False, records=10)
add_shared(t, knot, zones0, zones0[0])

t.start()
check_ksks(knot, zones0, zones0[1])

# testcase 2: adding zones to shared policy

zones_add1 = t.zone_rnd(5, dnssec=False, records=10)
add_shared(t, knot, zones_add1, zones0[0])

knot.gen_confile()
knot.reload()
check_ksks(knot, zones0 + zones_add1, zones0[1])

# testcase 3: adding zones to damaged shared policy .. generate new KSK and continue

# now purge zones keys in order to create dangling policy_last
for z in zones0:
    knot.ctl("zone-purge -f +kaspdb " + z.name)

zones_add2 = t.zone_rnd(5, dnssec=False, records=10)
add_shared(t, knot, zones_add2, zones0[0])

knot.gen_confile()
knot.reload()
check_ksks(knot, zones_add1, zones_add1[1])
check_ksks(knot, zones_add2, zones_add2[1])

add1_ksk = query_ksk(knot, zones_add1[1])
add2_ksk = query_ksk(knot, zones_add2[1])
if add1_ksk == add2_ksk:
    set_err("KSK NOT DIFFERENT (%s versus %s)" % (zones_add1[1].name, zones_add2[1].name))

t.end()
