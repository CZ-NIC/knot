#!/usr/bin/env python3

"""
Test of offline signing using KSR and SKR with pre-planned KSK rollover and automatic ZSK rollover.
"""

import collections
import os
import shutil
import datetime
import subprocess
import time
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

def writef(filename, contents):
    with open(filename, "w") as f:
        f.write(contents)

t = Test()

knot = t.server("knot")
ZONE = "example.com."
FUTURE = 100
TICK = 5
STARTUP = 10

zone = t.zone(ZONE)
t.link(zone, knot)

knot.zonefile_sync = 24 * 60 * 60

knot.dnssec(zone).enable = True
knot.dnssec(zone).manual = True
knot.dnssec(zone).alg = "ECDSAP384SHA384"
knot.dnssec(zone).dnskey_ttl = 2
knot.dnssec(zone).zsk_lifetime = STARTUP + 6*TICK # see ksk1 lifetime
knot.dnssec(zone).ksk_lifetime = 300 # this can be possibly left also infinity
knot.dnssec(zone).propagation_delay = TICK-2
knot.dnssec(zone).cds_publish = "none"
knot.port = 1234 # dummy, will be overwritten
knot.gen_confile()

def tickf(when):
    return "+%d" % (STARTUP + when * TICK)

# generate keys, including manual KSK rollover on the beginning
key_ksk1 = knot.key_gen(ZONE, ksk="true", created="+0", publish="+0", ready="+0", active="+0", retire=tickf(4), remove=tickf(5))
key_ksk2 = knot.key_gen(ZONE, ksk="true", created="+0", publish=tickf(2), ready=tickf(3), active=tickf(4), retire="+2h", remove="+3h")
key_zsk1 = knot.key_gen(ZONE, ksk="false", created="+0", publish="+0", active="+0")

# signer knot, copy everything from "knot"
signer = t.server("knot")
t.link(zone, signer)
signer.zones[ZONE].dnssec = knot.zones[ZONE].dnssec
signer.port = 1235
signer.gen_confile()
_, keys_list, _ = Keymgr.run_check(knot.confile, ZONE, "list")
for keyparm in keys_list.splitlines():
    pem = knot.keydir + "/keys/" + keyparm.split()[0] + ".pem"
    parm1 = keyparm.split()[1]
    parm2 = keyparm.replace("-", "_").split()[6:]
    Keymgr.run_check(signer.confile, ZONE, "import-pem", pem, parm1, *parm2)

# delete KSKs in "knot" and ZSKs in "signer"
os.remove(knot.keydir + "/keys/" + key_ksk1 + ".pem")
os.remove(knot.keydir + "/keys/" + key_ksk2 + ".pem")
os.remove(signer.keydir + "/keys/" + key_zsk1 + ".pem")

# pregenerate keys, exchange KSR, pre-sign it, exchange SKR
KSR = knot.keydir + "/ksr"
SKR = knot.keydir + "/skr"
Keymgr.run_check(knot.confile, ZONE, "pregenerate", str(FUTURE))
_, out, _ = Keymgr.run_check(knot.confile, ZONE, "generate-ksr", str(FUTURE))
writef(KSR, out)
_, out, _ = Keymgr.run_check(signer.confile, ZONE, "sign-ksr", KSR)
writef(SKR, out)
Keymgr.run_check(knot.confile, ZONE, "import-skr", SKR)

TICK_SAFE = TICK + TICK // 2;

# run it and see if the signing and rollovers work well
t.start()
knot.zone_wait(zone)
check_zone(knot, zone, 2, 1, 1, "init")

wait_for_dnskey_count(t, knot, 3, STARTUP + TICK_SAFE)
check_zone(knot, zone, 3, 1, 1, "KSK rollover: publish")

wait_for_rrsig_count(t, knot, "DNSKEY", 2, TICK_SAFE)
check_zone(knot, zone, 3, 2, 1, "KSK rollover: submission")

wait_for_rrsig_count(t, knot, "DNSKEY", 1, TICK_SAFE)
check_zone(knot, zone, 3, 1, 1, "KSK rollover: retired")

wait_for_dnskey_count(t, knot, 2, TICK_SAFE)
check_zone(knot, zone, 2, 1, 1, "KSK rollover: finished")

wait_for_dnskey_count(t, knot, 3, TICK_SAFE)
check_zone(knot, zone, 3, 1, 1, "ZSK rollover: running")

wait_for_dnskey_count(t, knot, 2, TICK_SAFE*2)
check_zone(knot, zone, 2, 1, 1, "ZSK rollover: done")

t.end()
