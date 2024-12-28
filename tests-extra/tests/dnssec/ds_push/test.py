#!/usr/bin/env python3

"""
Check of automatic KSK rollover with DS push.
"""

from dnstest.utils import *
from dnstest.keys import Keymgr
from dnstest.test import Test

import os
import random
import shutil

def pregenerate_key(server, zone, alg):
    class a_class_with_name:
        def __init__(self, name):
            self.name = name

    server.gen_key(a_class_with_name("nonexistent.zone."), ksk=True, alg=alg,
                   addtopolicy=zone[0].name)

# check zone if keys are present and used for signing
def check_zone(server, zone, dnskeys, dnskey_rrsigs, cdnskeys, soa_rrsigs, msg):
    qdnskeys = server.dig(zone.name, "DNSKEY", bufsize=4096)
    found_dnskeys = qdnskeys.count("DNSKEY")

    qdnskeyrrsig = server.dig(zone.name, "DNSKEY", dnssec=True, bufsize=4096)
    found_rrsigs = qdnskeyrrsig.count("RRSIG")

    qcdnskey = server.dig(zone.name, "CDNSKEY", bufsize=4096)
    found_cdnskeys = qcdnskey.count("CDNSKEY")

    qsoa = server.dig(zone.name, "SOA", dnssec=True, bufsize=4096)
    found_soa_rrsigs = qsoa.count("RRSIG")

    check_log("DNSKEYs: %d (expected %d)" % (found_dnskeys, dnskeys))
    check_log("RRSIGs: %d (expected %d)" % (found_soa_rrsigs, soa_rrsigs))
    check_log("DNSKEY-RRSIGs: %d (expected %d)" % (found_rrsigs, dnskey_rrsigs))
    check_log("CDNSKEYs: %d (expected %d)" % (found_cdnskeys, cdnskeys))

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

def wait_for_rrsig_count(t, server, zone, rrtype, rrsig_count, timeout):
    rtime = 0.0
    while True:
        qdnskeyrrsig = server.dig(zone.name, rrtype, dnssec=True, bufsize=4096)
        found_rrsigs = qdnskeyrrsig.count("RRSIG")
        if found_rrsigs == rrsig_count:
            break
        rtime = rtime + 0.1
        t.sleep(0.1)
        if rtime > timeout:
            break

def wait_for_dnskey_count(t, server, zone, dnskey_count, timeout):
    rtime = 0.0
    while True:
        qdnskeyrrsig = server.dig(zone.name, "DNSKEY", dnssec=True, bufsize=4096)
        found_dnskeys = qdnskeyrrsig.count("DNSKEY")
        if found_dnskeys == dnskey_count:
            break
        rtime = rtime + 0.1
        t.sleep(0.1)
        if rtime > timeout:
            break

def watch_ksk_rollover(t, server, zone, before_keys, after_keys, total_keys, desc):
    check_zone(server, zone, before_keys, 1, 1, 1, desc + ": initial keys")

    server.ctl("zone-key-rollover %s ksk" % zone.name)
    qdnskeys = server.dig(zone.name, "DNSKEY", bufsize=4096)
    t.sleep(server.dnssec(zone).propagation_delay + qdnskeys.resp.answer[0].ttl)

    check_zone(server, zone, total_keys, 2, 1, 1 if before_keys > 1 else 2, desc + ": both keys active")

    wait_for_rrsig_count(t, server, zone, "DNSKEY", 1, 24)
    check_zone(server, zone, after_keys, 1, 1, 1, desc + ": old key removed")

t = Test(tsig=False)

parent = t.server("knot")
parent_zone = t.zone_rnd(1)
t.link(parent_zone, parent, ddns=True)

parent.dnssec(parent_zone).enable = True

ZONE = "sub." * random.randint(1, 8) + parent_zone[0].name
child_zf = t.out_dir + "/" + ZONE + "zone"
shutil.copyfile(t.data_dir + "generic.zone" , child_zf)

child = t.server("knot")
child_zone = t.zone(ZONE, file_name=child_zf)
t.link(child_zone, child)

child.zonefile_sync = 24 * 60 * 60

child.dnssec(child_zone).enable = True
child.dnssec(child_zone).manual = False
child.dnssec(child_zone).alg = "ECDSAP256SHA256"
child.dnssec(child_zone).dnskey_ttl = 2
child.dnssec(child_zone).zsk_lifetime = 99999
child.dnssec(child_zone).ksk_lifetime = 300 # this can be possibly left also infinity
child.dnssec(child_zone).propagation_delay = 4
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

t.sleep(9)

pregenerate_key(child, child_zone, "ECDSAP256SHA256")
watch_ksk_rollover(t, child, child_zone[0], 2, 2, 3, "KSK rollover")

resp = parent.dig(ZONE, "DS")
resp.check_count(1, rtype="DS")
if resp.resp.answer[0].ttl != child.dnssec(child_zone).dnskey_ttl:
    set_err("DS TTL")

child.dnssec(child_zone).ds_push = "" # empty list []
child.gen_confile()
child.reload()
child.ctl("zone-key-rollover %s ksk" % child_zone[0].name)
t.sleep(20)
check_zone(child, child_zone[0], 3, 2, 1, 1, "empty DS push")

t.end()
