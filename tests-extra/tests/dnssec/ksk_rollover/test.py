#!/usr/bin/env python3

"""
More precise check of simple KSK rollover.

The key_rollovers test is too over-complicated already, unable to add test cases.
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

# check zone if keys are present and used for signing
def check_zone(server, zone, slave, dnskeys, dnskey_rrsigs, cdnskeys, soa_rrsigs, msg):

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

def wait_for_count(t, server, rrtype, count, min_time, timeout, msg):
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
    check_min_time(min_time, msg)

def get_cds(server):
    cds_rr = server.dig("example.com.", "CDS").resp.answer
    if len(cds_rr) == 0:
        return ""
    return str(cds_rr[0].to_rdataset())

def wait_for_cds_change(t, server, min_time, timeout, msg):
    rtime = 0
    CDS1 = get_cds(server)
    while True:
        CDS2 = get_cds(server)
        if CDS1 != CDS2:
            break
        rtime = rtime + 1
        t.sleep(1)
        if rtime > timeout:
            break
    check_min_time(min_time, msg)

def watch_ksk_rollover(t, server, zone, before_keys, after_keys, total_keys, desc, set_stss, set_ksk_lifetime, submission_cb):
    msg = desc + ": initial keys"
    check_zone(server, zone, server, before_keys, 1, 0, 1, msg)

    for z in zone:
        server.ctl("zone-key-rollover %s ksk" % z.name)

    msg = desc + ": published new"
    wait_for_count(t, server, "DNSKEY", total_keys, 0, 10, msg)
    check_zone(server, zone, server, total_keys, 2, 0, 1, msg)

    msg = desc + ": new KSK ready"
    wait_for_cds_change(t, server, 15, 26, msg) # propagation-delay + dnskey_ttl
    check_zone(server, zone, server, total_keys, 2, 1, 1, msg)

    submission_cb()
    msg = desc + ": both still active"
    wait_for_cds_change(t, server, 0, 10, msg)
    check_zone(server, zone, server, total_keys, 2, 0, 1, msg)

    msg = desc + ": old key removed"
    wait_for_count(t, server, "DNSKEY", after_keys, 10, 20, msg) # ds_ttl
    check_zone(server, zone, server, after_keys, 1, 0, 1, msg)

t = Test()

parent = t.server("knot")
parent_zone = t.zone("com.", storage=".")
t.link(parent_zone, parent)
parent.dnssec(parent_zone).enable = True

child = t.server("knot")
child_zone = t.zone("example.com.")
t.link(child_zone, child, ixfr=True)

def cds_submission():
    cds = child.dig("example.com.", "CDS")
    up = parent.update(parent_zone)
    up.delete("example.com.", "DS")
    for rd in cds.resp.answer[0].to_rdataset():
        up.add("example.com.", 11, "DS", rd.to_text())
    up.send("NOERROR")

child.dnssec(child_zone).enable = True
child.dnssec(child_zone).dnskey_ttl = 6
child.dnssec(child_zone).propagation_delay = 11
child.dnssec(child_zone).ksk_sbm_check = [ parent ]
child.dnssec(child_zone).ksk_sbm_check_interval = 3
child.dnssec(child_zone).cds_publish = "rollover"

t.start()
child.zone_wait(child_zone)

cds_submission()
t.sleep(5)

watch_ksk_rollover(t, child, child_zone, 2, 2, 3, "KSK rollover", None, 27, cds_submission)

t.end()
