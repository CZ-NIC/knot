#!/usr/bin/env python3

"""
Test of offline KSK by trying pre-generated ZSK rollover.
"""

import collections
import os
import shutil
import datetime
import subprocess
from subprocess import check_call

from dnstest.utils import *
from dnstest.keys import Keymgr
from dnstest.test import Test

# check zone if keys are present and used for signing
def check_zone(server, zone, dnskeys, dnskey_rrsigs, soa_rrsigs, msg):
    qdnskeys = server.dig("example.com", "DNSKEY", bufsize=4096)
    found_dnskeys = qdnskeys.count("DNSKEY")

    qdnskeyrrsig = server.dig("example.com", "DNSKEY", dnssec=True, bufsize=4096)
    found_rrsigs = qdnskeyrrsig.count("RRSIG")

    qsoa = server.dig("example.com", "SOA", dnssec=True, bufsize=4096)
    found_soa_rrsigs = qsoa.count("RRSIG")

    check_log("DNSKEYs: %d (expected %d)" % (found_dnskeys, dnskeys));
    check_log("RRSIGs: %d (expected %d)" % (found_soa_rrsigs, soa_rrsigs));
    check_log("DNSKEY-RRSIGs: %d (expected %d)" % (found_rrsigs, dnskey_rrsigs));

    if found_dnskeys != dnskeys:
        set_err("BAD DNSKEY COUNT: " + msg)
        detail_log("!DNSKEYs not published and activated as expected: " + msg)

    if found_soa_rrsigs != soa_rrsigs:
        set_err("BAD RRSIG COUNT: " + msg)
        detail_log("!RRSIGs not published and activated as expected: " + msg)

    if found_rrsigs != dnskey_rrsigs:
        set_err("BAD DNSKEY RRSIG COUNT: " + msg)
        detail_log("!RRSIGs not published and activated as expected: " + msg)

    detail_log(SEP)

    # Valgrind delay breaks the timing!
    if not server.valgrind:
        server.zone_backup(zone, flush=True)
        server.zone_verify(zone)

def wait_for_rrsig_count(t, server, rrtype, rrsig_count, timeout):
    rtime = 0
    while True:
        qdnskeyrrsig = server.dig("example.com", rrtype, dnssec=True, bufsize=4096)
        found_rrsigs = qdnskeyrrsig.count("RRSIG")
        if found_rrsigs == rrsig_count:
            break
        rtime = rtime + 1
        t.sleep(1)
        if rtime > timeout:
            break

def wait_for_dnskey_count(t, server, dnskey_count, timeout):
    for rtime in range(1, timeout):
        qdnskeyrrsig = server.dig("example.com", "DNSKEY", dnssec=True, bufsize=4096)
        found_dnskeys = qdnskeyrrsig.count("DNSKEY")
        if found_dnskeys == dnskey_count:
            break
        t.sleep(1)

t = Test()

knot = t.server("knot")
ZONE = "example.com."
zone = t.zone(ZONE)
t.link(zone, knot)

knot.zonefile_sync = 24 * 60 * 60

knot.dnssec(zone).enable = True
knot.dnssec(zone).manual = True
knot.dnssec(zone).alg = "ECDSAP384SHA384"
knot.dnssec(zone).dnskey_ttl = 2
knot.dnssec(zone).zsk_lifetime = 12
knot.dnssec(zone).ksk_lifetime = 300 # this can be possibly left also infinity
knot.dnssec(zone).propagation_delay = 3
knot.port = 1234 # dummy, will be overwritten
knot.gen_confile()

key_ksk = knot.gen_key(zone, ksk=True, alg="ECDSAP384SHA384", key_len=384)
key_zsk = knot.gen_key(zone, ksk=False, alg="ECDSAP384SHA384", key_len=384)

Keymgr.run_check(knot.confile, ZONE, "pregenerate", "100")

os.remove(knot.keydir + "/keys/" + key_ksk.keyid + ".pem")

# parameters

t.start()
knot.zone_wait(zone)
check_zone(knot, zone, 2, 1, 1, "init")

wait_for_dnskey_count(t, knot, 3, knot.dnssec(zone).zsk_lifetime)
check_zone(knot, zone, 3, 1, 1, "ZSK rollover")

t.sleep(2)

wait_for_dnskey_count(t, knot, 2, 2 * (knot.dnssec(zone).propagation_delay + knot.dnssec(zone).dnskey_ttl))
check_zone(knot, zone, 2, 1, 1, "end")

t.end()
