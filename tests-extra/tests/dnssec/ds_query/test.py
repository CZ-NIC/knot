#!/usr/bin/env python3

"""
Check of DS query planning.
"""

from dnstest.utils import *
from dnstest.keys import Keymgr
from dnstest.test import Test

# check zone if keys are present and used for signing
def check_zone(server, zone, dnskeys, dnskey_rrsigs, cdnskeys, soa_rrsigs, msg):
    qdnskeys = server.dig("example.com", "DNSKEY", bufsize=4096)
    found_dnskeys = qdnskeys.count("DNSKEY")

    qdnskeyrrsig = server.dig("example.com", "DNSKEY", dnssec=True, bufsize=4096)
    found_rrsigs = qdnskeyrrsig.count("RRSIG")

    qcdnskey = server.dig("example.com", "CDNSKEY", bufsize=4096)
    found_cdnskeys = qcdnskey.count("CDNSKEY")

    qsoa = server.dig("example.com", "SOA", dnssec=True, bufsize=4096)
    found_soa_rrsigs = qsoa.count("RRSIG")

    check_log("DNSKEYs: %d (expected %d)" % (found_dnskeys, dnskeys));
    check_log("RRSIGs: %d (expected %d)" % (found_soa_rrsigs, soa_rrsigs));
    check_log("DNSKEY-RRSIGs: %d (expected %d)" % (found_rrsigs, dnskey_rrsigs));
    check_log("CDNSKEYs: %d (expected %d)" % (found_cdnskeys, cdnskeys));

    if found_dnskeys != dnskeys:
        set_err("BAD DNSKEY COUNT: " + msg)
        detail_log("!DNSKEYs not published and activated as expected: " + msg)

    if found_soa_rrsigs != soa_rrsigs:
        set_err("BAD RRSIG COUNT: " + msg)
        detail_log("!RRSIGs not published and activated as expected: " + msg)

    if found_rrsigs != dnskey_rrsigs:
        set_err("BAD DNSKEY RRSIG COUNT: " + msg)
        detail_log("!RRSIGs not published and activated as expected: " + msg)

    if found_cdnskeys != cdnskeys:
        set_err("BAD CDNSKEY COUNT: " + msg)
        detail_log("!CDNSKEYs not published and activated as expected: " + msg)

    detail_log(SEP)


def wait_for_count(t, server, rrtype, count, timeout):
    rtime = 0
    while True:
        q = server.dig("example.com", rrtype, dnssec=True, bufsize=4096)
        found = q.count(rrtype)
        if found == count:
            break
        rtime = rtime + 1
        t.sleep(1)
        if rtime > timeout:
            break

t = Test()

parent = t.server("knot")
parent_zone = t.zone("com.", storage=".")
t.link(parent_zone, parent)

#parent.dnssec(parent_zone).enable = True

child = t.server("knot")
child_zone = t.zone("example.com.", storage=".")
t.link(child_zone, child)

def cds_submission():
    cds = child.dig(ZONE, "CDS")
    cds_rdata = cds.resp.answer[0].to_rdataset()[0].to_text()
    up = parent.update(parent_zone)
    up.add(ZONE, 7, "DS", cds_rdata)
    up.send("NOERROR")

child.zonefile_sync = 24 * 60 * 60

child.dnssec(child_zone).enable = True
child.dnssec(child_zone).manual = False
child.dnssec(child_zone).alg = "ECDSAP384SHA384"
child.dnssec(child_zone).dnskey_ttl = 2
child.dnssec(child_zone).zsk_lifetime = 99999
child.dnssec(child_zone).ksk_lifetime = 9999
child.dnssec(child_zone).propagation_delay = 4
child.dnssec(child_zone).ksk_sbm_check_interval = 2

# parameters
ZONE = "example.com."

t.start()
child.zone_wait(child_zone)

cds_submission()

child.dnssec(child_zone).ksk_sbm_check = [ parent ]
child.dnssec(child_zone).ksk_lifetime = 13
child.gen_confile()

child.reload()

wait_for_count(t, child, "DNSKEY", 3, 20) # initiation of KSK rollover means the initial submission was successful
check_zone(child, child_zone, 3, 2, 0, 1, "KSK rollover start")

child.dnssec(child_zone).ksk_sbm_check = [ ]
child.dnssec(child_zone).ksk_lifetime = 150
child.gen_confile()

child.reload()

t.sleep(6)
cds_submission()
t.sleep(1)

child.dnssec(child_zone).ksk_sbm_check = [ parent ]
child.gen_confile()

child.reload()

wait_for_count(t, child, "DNSKEY", 2, 20) # finalization of KSK rollover means the rollover submission was successful
check_zone(child, child_zone, 2, 1, 0, 1, "KSK rollover end")

t.end()
