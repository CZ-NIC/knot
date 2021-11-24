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

PUB_ONLY_SCENARIO = random.choice([0, 1, 2])
PUB_ONLY_KEYS = 1 if PUB_ONLY_SCENARIO > 0 else 0
PUB_ONLY_CDS = 1 if PUB_ONLY_SCENARIO > 1 else 0
PUB_ONLY_KEYID = ""
DELETE_DELAY = random.choice([0, 2, 7, 17, 117])

DOUBLE_DS = random.choice([True, False])
CDS_DT = random.choice(["sha256", "sha384"])
check_log("DOUBLE DS %s, cds dt %s, PUB_ONLY_KEYS %d, PUB_ONLY_CDS %d DELETE_DELAY %d" % \
          (str(DOUBLE_DS), CDS_DT, PUB_ONLY_KEYS, PUB_ONLY_CDS, DELETE_DELAY))

def generate_public_only(server, zone, alg):
    global PUB_ONLY_KEYID
    if PUB_ONLY_KEYID != "":
        Keymgr.run_check(server.confile, zone.name, "delete", PUB_ONLY_KEYID)

    if PUB_ONLY_KEYS == 0:
        return
    _, keymgr_stdout, _ = Keymgr.run_check(server.confile, zone.name, "import-pub", \
                                           t.data_dir + "/public-only-%s.key" % alg)
    PUB_ONLY_KEYID = keymgr_stdout.split('\n')[0]

    if PUB_ONLY_CDS == 0:
        return
    Keymgr.run_check(server.confile, zone.name, "set", PUB_ONLY_KEYID, "ready=+0")

def pregenerate_key(server, zone, alg):
    class a_class_with_name:
        def __init__(self, name):
            self.name = name

    server.gen_key(a_class_with_name("nonexistent.zone."), ksk=True, alg=alg,
                   addtopolicy=zone[0].name)

# check zone if keys are present and used for signing
def check_zone(server, zone, slave, dnskeys, dnskey_rrsigs, cdnskeys, soa_rrsigs, msg):
    dnskeys += PUB_ONLY_KEYS
    cdnskeys += PUB_ONLY_CDS

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

    serial = server.zone_wait(zone)
    slave.zone_wait(zone, serial, equal=True, greater=False)
    t.xfr_diff(server, slave, zone)

    server.zone_backup(zone, flush=True)
    server.zone_verify(zone, ldns_check=False) # ldns-verify-zone complains about RRSIG without corresponding DNSKEY

global_last_roll = 0

def check_min_time(min_time, msg):
    global global_last_roll
    prev_roll = global_last_roll
    global_last_roll = time.time()

    if global_last_roll - prev_roll < min_time:
        set_err("Too early roll: " + msg)
        detail_log("!Roll-over went too fast (%d < %d): %s" % (global_last_roll - prev_roll, min_time, msg))

def wait_for_rrsig_count(t, server, rrtype, rrsig_count, min_time, timeout, msg):
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
    check_min_time(min_time, msg)

def wait_for_count(t, server, rrtype, count, min_time, timeout, msg):
    rtime = 0

    if rrtype == "DNSKEY":
        count += PUB_ONLY_KEYS
    if rrtype == "CDNSKEY" or rrtype == "CDS":
        count += PUB_ONLY_CDS

    while True:
        q = server.dig("example.com", rrtype, dnssec=True, bufsize=4096)
        found = q.count(rrtype)
        if found == count:
            break
        rtime = rtime + 1
        t.sleep(1)
        if rtime > timeout:
            break
    check_min_time(min_time, msg)

def wait_for_cds_change(t, server, min_time, timeout, msg):
    rtime = 0
    CDS1 = str(server.dig(ZONE, "CDS").resp.answer[0].to_rdataset())
    while True:
        CDS2 = str(server.dig(ZONE, "CDS").resp.answer[0].to_rdataset())
        if CDS1 != CDS2:
            break
        rtime = rtime + 1
        t.sleep(1)
        if rtime > timeout:
            break
    check_min_time(min_time, msg)

def wait_after_submission(t, server):
    if DOUBLE_DS:
        wait_for_count(t, server, "CDNSKEY", 1, 0, 10, "after submission")
    else:
        t.sleep(4)

def watch_alg_rollover(t, server, zone, slave, before_keys, after_keys, desc, set_alg, set_stss, submission_cb):
    msg = desc + ": initial keys"
    check_zone(server, zone, slave, before_keys, 1, 1, 1, msg)

    if set_stss is not None:
        server.dnssec(zone).single_type_signing = set_stss
    server.dnssec(zone).alg = set_alg
    server.gen_confile()
    server.reload()

    msg = desc + ": pre active"
    wait_for_rrsig_count(t, server, "SOA", 2, 0, 20, msg)
    check_zone(server, zone, slave, before_keys, 1, 1, 2, msg)

    msg = desc + ": both algorithms active"
    wait_for_count(t, server, "DNSKEY", before_keys + after_keys, 13, 20, msg)
    check_zone(server, zone, slave, before_keys + after_keys, 2, 1, 2, msg)

    generate_public_only(server, zone[0], set_alg)

    # wait for any change in CDS records
    CDS1 = str(server.dig(ZONE, "CDS").resp.answer[0].to_rdataset())
    t.sleep(1)
    while CDS1 == str(server.dig(ZONE, "CDS").resp.answer[0].to_rdataset()):
      t.sleep(1)

    cdnskeys = 2 if DOUBLE_DS else 1
    msg = desc + ": new KSK ready"
    check_zone(server, zone, slave, before_keys + after_keys, 2, cdnskeys, 2, msg)

    submission_cb()
    msg = desc + ": both still active"
    wait_after_submission(t, server)
    check_zone(server, zone, slave, before_keys + after_keys, 2, 1, 2, msg)

    msg = desc + ": post active"
    wait_for_count(t, server, "DNSKEY", after_keys, 5, 20, msg)
    check_zone(server, zone, slave, after_keys, 1, 1, 2, msg)

    msg = desc + ": old alg removed"
    wait_for_rrsig_count(t, server, "SOA", 1, 11, 17, msg)
    check_zone(server, zone, slave, after_keys, 1, 1, 1, msg)

def watch_ksk_rollover(t, server, zone, slave, before_keys, after_keys, total_keys, desc, set_stss, set_ksk_lifetime, submission_cb):
    msg = desc + ": initial keys"
    check_zone(server, zone, slave, before_keys, 1, 1, 1, msg)

    if set_stss is not None:
        server.dnssec(zone).single_type_signing = set_stss
        server.gen_confile()
        server.reload()
    else:
        for z in zone:
            server.ctl("zone-key-rollover %s ksk" % z.name)

    msg = desc + ": published new"
    wait_for_count(t, server, "DNSKEY", total_keys, 0, 20, msg)
    check_zone(server, zone, slave, total_keys, 2, 1, 1, msg)

    msg = desc + ": new KSK ready"
    wait_for_cds_change(t, server, 10, 20, msg)
    cdnskeys = 2 if DOUBLE_DS else 1
    expect_zone_rrsigs = (2 if before_keys == 1 and after_keys > 1 else 1) # there is an exception for CSK->KZSK rollover that we have double signatures for the zone. Sorry, we don't care...
    check_zone(server, zone, slave, total_keys, 2, cdnskeys, expect_zone_rrsigs, msg)

    t.sleep(server.dnssec(zone).propagation_delay + 1) # check that Knot does wait for the submission to succeed
    submission_cb()
    msg = desc + ": both still active"
    wait_after_submission(t, server)
    if before_keys < 2 or after_keys > 1:
        check_zone(server, zone, slave, total_keys, 2, 1, 1, msg)
    # else skip the test as we have no control on KSK and ZSK retiring asynchronously

    t.sleep(5) # cca DS TTL
    wait_for_count(t, server, "SOA", 1, 0, 1, "NOOP")

    msg = desc + ": old key removed"
    if before_keys > 1:
        wait_for_count(t, server, "DNSKEY", after_keys, 0, 10, msg)
    else:
        wait_for_count(t, server, "DNSKEY", after_keys, 14, 20, msg)
    check_zone(server, zone, slave, after_keys, 1, 1, 1, msg)

t = Test()

parent = t.server("knot")
parent_zone = t.zone("com.", storage=".")
t.link(parent_zone, parent)

parent.dnssec(parent_zone).enable = True

child = t.server("knot")
slave = t.server("knot")
child_zone = t.zone("example.com.", storage=".")
t.link(child_zone, child, slave, ixfr=True)

def cds_submission():
    cds = child.dig(ZONE, "CDS")
    up = parent.update(parent_zone)
    up.delete(ZONE, "DS")
    for rd in cds.resp.answer[0].to_rdataset():
        up.add(ZONE, 7, "DS", rd.to_text())
    up.send("NOERROR")

child.zonefile_sync = 24 * 60 * 60

child.dnssec(child_zone).enable = True
child.dnssec(child_zone).manual = False
child.dnssec(child_zone).alg = "ECDSAP384SHA384"
child.dnssec(child_zone).dnskey_ttl = 2
child.dnssec(child_zone).zsk_lifetime = 99999
child.dnssec(child_zone).ksk_lifetime = 300 # this can be possibly left also infinity
child.dnssec(child_zone).delete_delay = DELETE_DELAY
child.dnssec(child_zone).propagation_delay = 11
child.dnssec(child_zone).ksk_sbm_check = [ parent ]
child.dnssec(child_zone).ksk_sbm_check_interval = 2
child.dnssec(child_zone).ksk_shared = True
child.dnssec(child_zone).cds_publish = "always"
if DOUBLE_DS:
    child.dnssec(child_zone).cds_publish = "double-ds"
child.dnssec(child_zone).cds_digesttype = CDS_DT

# parameters
ZONE = "example.com."

t.start()
child.zone_wait(child_zone)
generate_public_only(child, child_zone[0], "ECDSAP384SHA384")

cds_submission()
t.sleep(5)

pregenerate_key(child, child_zone, "ECDSAP256SHA256")
watch_alg_rollover(t, child, child_zone, slave, 2, 1, "KZSK to CSK alg", "ECDSAP256SHA256", True, cds_submission)

pregenerate_key(child, child_zone, "ECDSAP256SHA256")
watch_ksk_rollover(t, child, child_zone, slave, 1, 1, 2, "CSK rollover", None, 27, cds_submission)

pregenerate_key(child, child_zone, "ECDSAP256SHA256")
watch_ksk_rollover(t, child, child_zone, slave, 1, 2, 3, "CSK to KZSK", False, 0, cds_submission)

pregenerate_key(child, child_zone, "ECDSAP256SHA256")
watch_ksk_rollover(t, child, child_zone, slave, 2, 2, 3, "KSK rollover", None, 27, cds_submission)

pregenerate_key(child, child_zone, "ECDSAP256SHA256")
watch_ksk_rollover(t, child, child_zone, slave, 2, 1, 3, "KZSK to CSK", True, 0, cds_submission)

pregenerate_key(child, child_zone, "ECDSAP384SHA384")
watch_alg_rollover(t, child, child_zone, slave, 1, 1, "CSK to CSK alg", "ECDSAP384SHA384", None, cds_submission)

pregenerate_key(child, child_zone, "ECDSAP256SHA256")
watch_alg_rollover(t, child, child_zone, slave, 1, 2, "CSK to KZSK alg", "ECDSAP256SHA256", False, cds_submission)

pregenerate_key(child, child_zone, "ECDSAP384SHA384")
watch_alg_rollover(t, child, child_zone, slave, 2, 2, "KZSK alg", "ECDSAP384SHA384", None, cds_submission)

t.end()
