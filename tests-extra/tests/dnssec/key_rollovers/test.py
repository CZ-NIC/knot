#!/usr/bin/env python3

"""
Check of automatic algorithm rollover scenario.
"""

import collections
import os
import random
import shutil
import datetime
import subprocess
from subprocess import check_call

from dnstest.utils import *
from dnstest.keys import Keymgr
from dnstest.test import Test

DOUBLE_DS = random.choice([True, False])
if DOUBLE_DS:
    check_log("DOUBLE DS ENABLED")

def pregenerate_key(server, zone, alg):
    class a_class_with_name:
        def __init__(self, name):
            self.name = name

    server.gen_key(a_class_with_name("notexisting.zone."), ksk=True, alg=alg,
                   addtopolicy=zone[0].name)

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

def wait_after_submission(t, server):
    if DOUBLE_DS:
        wait_for_count(t, server, "CDNSKEY", 1, 10)
    else:
        t.sleep(4)

def watch_alg_rollover(t, server, zone, before_keys, after_keys, desc, set_alg, set_stss, submission_cb):
    check_zone(server, zone, before_keys, 1, 1, 1, desc + ": initial keys")

    server.dnssec(zone).single_type_signing = set_stss
    server.dnssec(zone).alg = set_alg
    server.gen_confile()
    server.reload()

    wait_for_rrsig_count(t, server, "SOA", 2, 20)
    check_zone(server, zone, before_keys, 1 if after_keys > 1 else 2, 1, 2, desc + ": pre active")

    wait_for_count(t, server, "DNSKEY", before_keys + after_keys, 20)
    check_zone(server, zone, before_keys + after_keys, 2, 1, 2, desc + ": both algorithms active")

    # wait for any change in CDS records
    CDS1 = str(server.dig(ZONE, "CDS").resp.answer[0].to_rdataset())
    t.sleep(3)
    while CDS1 == str(server.dig(ZONE, "CDS").resp.answer[0].to_rdataset()):
      t.sleep(1)

    cdnskeys = 2 if DOUBLE_DS else 1
    check_zone(server, zone, before_keys + after_keys, 2, cdnskeys, 2, desc + ": new KSK ready")

    submission_cb()
    wait_after_submission(t, server)
    check_zone(server, zone, before_keys + after_keys, 2, 1, 2, desc + ": both still active")

    wait_for_count(t, server, "DNSKEY", after_keys, 20)
    check_zone(server, zone, after_keys, 1 if before_keys > 1 else 2, 1, 2, desc + ": post active")

    wait_for_rrsig_count(t, server, "SOA", 1, 20)
    check_zone(server, zone, after_keys, 1, 1, 1, desc + ": old alg removed")

def watch_ksk_rollover(t, server, zone, before_keys, after_keys, total_keys, desc, set_stss, set_ksk_lifetime, submission_cb):
    check_zone(server, zone, before_keys, 1, 1, 1, desc + ": initial keys")
    orig_ksk_lifetime = server.dnssec(zone).ksk_lifetime

    server.dnssec(zone).single_type_signing = set_stss
    server.dnssec(zone).ksk_lifetime = set_ksk_lifetime if set_ksk_lifetime > 0 else orig_ksk_lifetime
    server.gen_confile()
    server.reload()

    wait_for_count(t, server, "DNSKEY", total_keys, 20)

    t.sleep(3)
    check_zone(server, zone, total_keys, 1, 1, 1, desc + ": published new")

    wait_for_rrsig_count(t, server, "DNSKEY", 2, 20)
    cdnskeys = 2 if DOUBLE_DS else 1
    check_zone(server, zone, total_keys, 2, cdnskeys, 1 if before_keys > 1 and after_keys > 1 else 2, desc + ": new KSK ready")

    server.dnssec(zone).ksk_lifetime = orig_ksk_lifetime
    server.gen_confile()
    server.reload()

    t.sleep(server.dnssec(zone).propagation_delay + 1) # check that Knot does wait for the submittion to succeed
    submission_cb()
    wait_after_submission(t, server)
    if before_keys < 2 or after_keys > 1:
        check_zone(server, zone, total_keys, 2, 1, 1 if before_keys > 1 else 2, desc + ": both still active")
    # else skip the test as we have no control on KSK and ZSK retiring asynchronously

    wait_for_rrsig_count(t, server, "DNSKEY", 1, 20)
    if before_keys < 2 or after_keys > 1:
        check_zone(server, zone, total_keys, 1, 1, 1, desc + ": old key retired")
    # else skip the test as we have no control on KSK and ZSK retiring asynchronously

    wait_for_count(t, server, "DNSKEY", after_keys, 20)
    check_zone(server, zone, after_keys, 1, 1, 1, desc + ": old key removed")

t = Test()

parent = t.server("knot")
parent_zone = t.zone("com.", storage=".")
t.link(parent_zone, parent)

parent.dnssec(parent_zone).enable = True

child = t.server("knot")
child_zone = t.zone("example.com.", storage=".")
t.link(child_zone, child)

def cds_submission():
    cds = child.dig(ZONE, "CDS")
    cds_rdata = cds.resp.answer[0].to_rdataset()[0].to_text()
    up = parent.update(parent_zone)
    up.add(ZONE, 7, "DS", cds_rdata)
    if DOUBLE_DS:
        try:
            cds_rdata = cds.resp.answer[0].to_rdataset()[1].to_text()
            up.add(ZONE, 7, "DS", cds_rdata)
        except:
            pass
    up.send("NOERROR")

child.zonefile_sync = 24 * 60 * 60

child.dnssec(child_zone).enable = True
child.dnssec(child_zone).manual = False
child.dnssec(child_zone).alg = "ECDSAP384SHA384"
child.dnssec(child_zone).dnskey_ttl = 2
child.dnssec(child_zone).zsk_lifetime = 99999
child.dnssec(child_zone).ksk_lifetime = 300 # this can be possibly left also infinity
child.dnssec(child_zone).propagation_delay = 11
child.dnssec(child_zone).ksk_sbm_check = [ parent ]
child.dnssec(child_zone).ksk_sbm_check_interval = 2
child.dnssec(child_zone).ksk_shared = True
if DOUBLE_DS:
    child.dnssec(child_zone).cds_publish = "double-ds"

# parameters
ZONE = "example.com."

t.start()
child.zone_wait(child_zone)

cds_submission()
t.sleep(5)

pregenerate_key(child, child_zone, "ECDSAP256SHA256")
watch_alg_rollover(t, child, child_zone, 2, 1, "KZSK to CSK alg", "ECDSAP256SHA256", True, cds_submission)

pregenerate_key(child, child_zone, "ECDSAP256SHA256")
watch_ksk_rollover(t, child, child_zone, 1, 1, 2, "CSK rollover", True, 27, cds_submission)

pregenerate_key(child, child_zone, "ECDSAP256SHA256")
watch_ksk_rollover(t, child, child_zone, 1, 2, 3, "CSK to KZSK", False, 0, cds_submission)

pregenerate_key(child, child_zone, "ECDSAP256SHA256")
watch_ksk_rollover(t, child, child_zone, 2, 2, 3, "KSK rollover", False, 27, cds_submission)

pregenerate_key(child, child_zone, "ECDSAP256SHA256")
watch_ksk_rollover(t, child, child_zone, 2, 1, 3, "KZSK to CSK", True, 0, cds_submission)

pregenerate_key(child, child_zone, "ECDSAP384SHA384")
watch_alg_rollover(t, child, child_zone, 1, 1, "CSK to CSK alg", "ECDSAP384SHA384", True, cds_submission)

pregenerate_key(child, child_zone, "ECDSAP256SHA256")
watch_alg_rollover(t, child, child_zone, 1, 2, "CSK to KZSK alg", "ECDSAP256SHA256", False, cds_submission)

pregenerate_key(child, child_zone, "ECDSAP384SHA384")
watch_alg_rollover(t, child, child_zone, 2, 2, "KZSK alg", "ECDSAP384SHA384", False, cds_submission)

t.end()
