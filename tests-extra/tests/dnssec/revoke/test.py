#!/usr/bin/env python3

"""
Test of setting KSK to RFC 5011 revoke state.
"""

from dnstest.utils import *
from dnstest.keys import Keymgr
from dnstest.test import Test

ZONE = "example.com."

# check zone if keys are present and used for signing
def check_zone(server, zone, dnskeys, dnskey_rrsigs, cdnskeys, soa_rrsigs, msg):
    qdnskeys = server.dig(ZONE, "DNSKEY", bufsize=4096)
    found_dnskeys = qdnskeys.count("DNSKEY")

    qdnskeyrrsig = server.dig(ZONE, "DNSKEY", dnssec=True, bufsize=4096)
    found_rrsigs = qdnskeyrrsig.count("RRSIG")

    qcdnskey = server.dig(ZONE, "CDNSKEY", bufsize=4096)
    found_cdnskeys = qcdnskey.count("CDNSKEY")

    qsoa = server.dig(ZONE, "SOA", dnssec=True, bufsize=4096)
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

    server.zone_backup(zone, flush=True)
    server.zone_verify(zone)

def wait_for_rrsig_count(t, server, rrtype, rrsig_count, timeout):
    rtime = 0
    while True:
        qdnskeyrrsig = server.dig(ZONE, rrtype, dnssec=True, bufsize=4096)
        found_rrsigs = qdnskeyrrsig.count("RRSIG")
        if found_rrsigs == rrsig_count:
            break
        rtime = rtime + 1
        t.sleep(1)
        if rtime > timeout:
            break

t = Test()

knot = t.server("knot")
zone = t.zone(ZONE)
t.link(zone, knot)
knot.dnssec(zone).enable = True
knot.dnssec(zone).manual = True

knot.gen_confile()

knot.key_gen(ZONE, ksk="true", zsk="true", created="+0", publish="+0", ready="+0", active="+0", retire="+13s", revoke="+16s", remove="+19s")
knot.key_gen(ZONE, ksk="true", zsk="true", created="+0", publish="+0", ready="+11s", active="+11s", retire="+1d", remove="+1d")

t.start()

knot.zone_wait(zone)
check_zone(knot, zone, 2, 1, 0, 1, "init")

wait_for_rrsig_count(t, knot, "DNSKEY", 2, 10)
check_zone(knot, zone, 2, 2, 0, 2, "roll")

wait_for_rrsig_count(t, knot, "DNSKEY", 1, 5)
check_zone(knot, zone, 2, 1, 0, 1, "retire")

wait_for_rrsig_count(t, knot, "DNSKEY", 2, 5)
check_zone(knot, zone, 2, 2, 0, 1, "revoke")

found = False
resp = knot.dig(ZONE, "DNSKEY")
for rr in resp.resp.answer[0].to_rdataset():
  if rr.to_text().split()[0] == "385":
    found = True

if not found:
  set_err("No revoked DNSKEY")
  detail_log("No revoked DNSKEY:")
  for rr in resp.resp.answer[0].to_rdataset():
    detail_log(rr.to_text())

t.end()
