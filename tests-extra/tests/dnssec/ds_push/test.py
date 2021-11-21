#!/usr/bin/env python3

"""
Check of automatic KSK rollover with DS push.
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

ZONE = "sub.example.com."

def pregenerate_key(server, zone, alg):
    class a_class_with_name:
        def __init__(self, name):
            self.name = name

    server.gen_key(a_class_with_name("nonexistent.zone."), ksk=True, alg=alg,
                   addtopolicy=zone[0].name)

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
    rtime = 0.0
    while True:
        qdnskeyrrsig = server.dig(ZONE, rrtype, dnssec=True, bufsize=4096)
        found_rrsigs = qdnskeyrrsig.count("RRSIG")
        if found_rrsigs == rrsig_count:
            break
        rtime = rtime + 0.1
        t.sleep(0.1)
        if rtime > timeout:
            break

def wait_for_dnskey_count(t, server, dnskey_count, timeout):
    rtime = 0.0
    while True:
        qdnskeyrrsig = server.dig(ZONE, "DNSKEY", dnssec=True, bufsize=4096)
        found_dnskeys = qdnskeyrrsig.count("DNSKEY")
        if found_dnskeys == dnskey_count:
            break
        rtime = rtime + 0.1
        t.sleep(0.1)
        if rtime > timeout:
            break

def watch_ksk_rollover(t, server, zone, before_keys, after_keys, total_keys, desc):
    check_zone(server, zone, before_keys, 1, 1, 1, desc + ": initial keys")

    server.ctl("zone-key-rollover %s ksk" % zone[0].name)

    wait_for_dnskey_count(t, server, total_keys, 20)
    check_zone(server, zone, total_keys, 2, 1, 1 if before_keys > 1 else 2, desc + ": both keys active")

    wait_for_rrsig_count(t, server, "DNSKEY", 1, 20)
    check_zone(server, zone, after_keys, 1, 1, 1, desc + ": old key removed")

t = Test(tsig=False)

parent = t.server("knot")
parent_zone = t.zone("com.", storage=".")
t.link(parent_zone, parent, ddns=True)

parent.dnssec(parent_zone).enable = True

child = t.server("knot")
child_zone = t.zone(ZONE, storage=".")
t.link(child_zone, child)

child.zonefile_sync = 24 * 60 * 60

child.dnssec(child_zone).enable = True
child.dnssec(child_zone).manual = False
child.dnssec(child_zone).alg = "ECDSAP256SHA256"
child.dnssec(child_zone).dnskey_ttl = 2
child.dnssec(child_zone).zsk_lifetime = 99999
child.dnssec(child_zone).ksk_lifetime = 300 # this can be possibly left also infinity
child.dnssec(child_zone).propagation_delay = 11
child.dnssec(child_zone).ksk_sbm_check = [ parent ]
child.dnssec(child_zone).ksk_sbm_check_interval = 2
child.dnssec(child_zone).ds_push = parent
child.dnssec(child_zone).ksk_shared = True
child.dnssec(child_zone).cds_publish = "always"

#t.start()
t.generate_conf()
parent.start()
t.sleep(2)
child.start()
child.zone_wait(child_zone)

t.sleep(5)

pregenerate_key(child, child_zone, "ECDSAP256SHA256")
watch_ksk_rollover(t, child, child_zone, 2, 2, 3, "KSK rollover")

resp = parent.dig(ZONE, "DS")
resp.check_count(1, rtype="DS")

t.end()
