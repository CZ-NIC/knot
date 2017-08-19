#!/usr/bin/env python3

"""
Check of automatic algorithm rollover scenario.
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
def check_zone(server, dnskeys, dnskey_rrsigs, cdnskeys, soa_rrsigs, msg):
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

t = Test()

parent = t.server("knot")
parent_zone = t.zone("com.", storage=".")
t.link(parent_zone, parent)

child = t.server("knot")
child_zone = t.zone("example.com.")
t.link(child_zone, child)

child.zonefile_sync = 24 * 60 * 60

child.dnssec(child_zone).enable = True
child.dnssec(child_zone).manual = False
child.dnssec(child_zone).alg = "RSASHA512"
child.dnssec(child_zone).dnskey_ttl = 2
child.dnssec(child_zone).zsk_lifetime = 99999
child.dnssec(child_zone).ksk_lifetime = 300 # this can be possibly left also infinity
child.dnssec(child_zone).propagation_delay = 11
child.dnssec(child_zone).ksk_sbm_check = [ parent ]
child.dnssec(child_zone).ksk_sbm_check_interval = 2

# parameters
ZONE = "example.com."

t.start()
child.zone_wait(child_zone)

check_zone(child, 2, 1, 1, 1, "initial keys")

child.dnssec(child_zone).alg = "RSASHA256"
child.gen_confile()
child.reload()

child.zone_wait(child_zone)
wait_for_rrsig_count(t, child, "SOA", 2, 20)

check_zone(child, 2, 1, 1, 2, "pre active")

wait_for_rrsig_count(t, child, "DNSKEY", 2, 20)

check_zone(child, 4, 2, 1, 2, "both algorithms active")

CDS1 = str(child.dig(ZONE, "CDS").resp.answer[0].to_rdataset())
t.sleep(3)
while CDS1 == str(child.dig(ZONE, "CDS").resp.answer[0].to_rdataset()):
  t.sleep(1)

check_zone(child, 4, 2, 1, 2, "new KSK ready")

cds = child.dig(ZONE, "CDS")
cds_rdata = cds.resp.answer[0].to_rdataset()[0].to_text()
up = parent.update(parent_zone)
up.add(ZONE, 3600, "DS", cds_rdata)
up.send("NOERROR")

t.sleep(4)

check_zone(child, 4, 2, 1, 2, "both still active")

wait_for_rrsig_count(t, child, "DNSKEY", 1, 20)

check_zone(child, 2, 1, 1, 2, "post active")

wait_for_rrsig_count(t, child, "SOA", 1, 20)

check_zone(child, 2, 1, 1, 1, "old alg removed")

t.end()
