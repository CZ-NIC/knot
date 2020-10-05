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
import random
from subprocess import check_call

from dnstest.utils import *
from dnstest.keys import Keymgr
from dnstest.test import Test

def cripple_skr(skr_in, skr_out):
    rrsigs_total = 9
    after_rrsig = -1000
    rrsig_now = 0
    rrsig_chosen = random.randint(1, rrsigs_total)
    with open(skr_in, "r") as fin:
        with open(skr_out, "w") as fout:
            for linein in fin:
                lineout = linein
                linesplit = linein.split()
                if len(linesplit) > 2 and linesplit[2] == "RRSIG":
                    after_rrsig = 0
                    rrsig_now += 1
                else:
                    after_rrsig += 1
                    if after_rrsig == 3 and rrsig_now == rrsig_chosen:
                        lineout = linein.lower() # this crippels the rrsig
                fout.write(lineout)

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

    server.zone_backup(zone, flush=True)
    server.zone_verify(zone)

def wait_for_rrsig_count(t, server, rrtype, rrsig_count, timeout):
    endtime = time.monotonic() + timeout - 0.5
    while True:
        qdnskeyrrsig = server.dig("example.com", rrtype, dnssec=True, bufsize=4096)
        found_rrsigs = qdnskeyrrsig.count("RRSIG")
        if found_rrsigs == rrsig_count:
            break

        # Verify the zone instead of a dumb sleep
        server.zone_backup(zone, flush=True)
        server.zone_verify(zone)

        if time.monotonic() > endtime:
            break

def wait_for_dnskey_count(t, server, dnskey_count, timeout):
    endtime = time.monotonic() + timeout - 0.5
    while True:
        qdnskeyrrsig = server.dig("example.com", "DNSKEY", dnssec=True, bufsize=4096)
        found_dnskeys = qdnskeyrrsig.count("DNSKEY")
        if found_dnskeys == dnskey_count:
            break

        # Verify the zone instead of a dumb sleep
        server.zone_backup(zone, flush=True)
        server.zone_verify(zone)

        if time.monotonic() > endtime:
            break

def writef(filename, contents):
    with open(filename, "w") as f:
        f.write(contents)

t = Test()

knot = t.server("knot")
ZONE = "example.com."
FUTURE = 55
TICK = 5
STARTUP = 10

zone = t.zone(ZONE)
t.link(zone, knot)

knot.zonefile_sync = 24 * 60 * 60

knot.dnssec(zone).enable = True
knot.dnssec(zone).manual = True
knot.dnssec(zone).alg = "ECDSAP384SHA384"
knot.dnssec(zone).dnskey_ttl = 2
knot.dnssec(zone).zone_max_ttl = 3
knot.dnssec(zone).zsk_lifetime = STARTUP + 6*TICK # see ksk1 lifetime
knot.dnssec(zone).ksk_lifetime = 300 # this can be possibly left also infinity
knot.dnssec(zone).propagation_delay = TICK-2
knot.dnssec(zone).offline_ksk = "on"
knot.dnssec(zone).cds_publish = "rollover"
knot.dnssec(zone).rrsig_lifetime = 15
knot.dnssec(zone).rrsig_refresh = 5
knot.dnssec(zone).rrsig_prerefresh = 1

# needed for keymgr
knot.gen_confile()

signer = t.server("knot")
t.link(zone, signer)
signer.zones[ZONE].dnssec = knot.zones[ZONE].dnssec

# needed for keymgr
signer.gen_confile()

def tickf(when):
    return "+%d" % (STARTUP + when * TICK)

# generate keys, including manual KSK rollover on the beginning
key_ksk1 = signer.key_gen(ZONE, ksk="true", created="+0", publish="+0", ready="+0", active="+0", retire=tickf(4), remove=tickf(5))
key_ksk2 = signer.key_gen(ZONE, ksk="true", created="+0", publish=tickf(2), ready=tickf(3), active=tickf(4), retire="+2h", remove="+3h")
key_zsk1 = knot.key_gen(ZONE, ksk="false", created="+0", publish="+0", active="+0")

# pregenerate keys, exchange KSR, pre-sign it, exchange SKR
KSR = knot.keydir + "/ksr"
SKR = knot.keydir + "/skr"
SKR_BROKEN = SKR + "_broken"
Keymgr.run_check(knot.confile, ZONE, "pregenerate", "+" + str(FUTURE))
_, out, _ = Keymgr.run_check(knot.confile, ZONE, "generate-ksr", "+0", "+" + str(FUTURE))
writef(KSR, out)
_, out, _ = Keymgr.run_check(signer.confile, ZONE, "sign-ksr", KSR)
writef(SKR, out)

cripple_skr(SKR, SKR_BROKEN)
_, out, _ = Keymgr.run_check(knot.confile, ZONE, "validate-skr", SKR_BROKEN)
if out.split()[0] != "error:":
    set_err("keymgr validate-skr")
    detail_log(out)
Keymgr.run_fail(knot.confile, ZONE, "import-skr", SKR_BROKEN)

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

# re-generate keys, re-eschange KSR and SKR and re-import it over previous

STARTUP = 1
signer.key_set(ZONE, key_ksk2, retire=tickf(3), remove=tickf(4))
key_ksk3 = signer.key_gen(ZONE, ksk="true", created="+0", publish=tickf(1), ready=tickf(2), active=tickf(3), retire="+4h", remove="+5h")

knot.dnssec(zone).zsk_lifetime = 8*TICK
knot.gen_confile()

KSR = KSR + "2"
SKR = SKR + "2"
Keymgr.run_check(knot.confile, ZONE, "pregenerate", "+" + str(FUTURE))
_, out, _ = Keymgr.run_check(knot.confile, ZONE, "generate-ksr", "+0", "+" + str(FUTURE))
writef(KSR, out)
_, out, _ = Keymgr.run_check(signer.confile, ZONE, "sign-ksr", KSR)
writef(SKR, out)
Keymgr.run_check(knot.confile, ZONE, "import-skr", SKR)

knot.ctl("zone-sign")

check_zone(knot, zone, 2, 1, 1, "init2")

wait_for_dnskey_count(t, knot, 3, STARTUP + TICK_SAFE)
check_zone(knot, zone, 3, 1, 1, "KSK rollover2: publish")

wait_for_rrsig_count(t, knot, "DNSKEY", 2, TICK_SAFE)
check_zone(knot, zone, 3, 2, 1, "KSK rollover2: submission")

wait_for_rrsig_count(t, knot, "DNSKEY", 1, TICK_SAFE)
check_zone(knot, zone, 3, 1, 1, "KSK rollover2: retired")

wait_for_dnskey_count(t, knot, 2, TICK_SAFE)
check_zone(knot, zone, 2, 1, 1, "KSK rollover2: finished")

wait_for_dnskey_count(t, knot, 3, TICK_SAFE*2)
check_zone(knot, zone, 3, 1, 1, "ZSK rollover2: running")

wait_for_dnskey_count(t, knot, 2, TICK_SAFE*2)
check_zone(knot, zone, 2, 1, 1, "ZSK rollover2: done")

t.end()
