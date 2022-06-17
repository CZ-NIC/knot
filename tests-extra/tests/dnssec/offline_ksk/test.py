#!/usr/bin/env python3

"""
Test of offline signing using KSR and SKR with pre-planned KSK rollover and automatic ZSK rollover.
"""

import random

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
    first = True
    while True:
        qdnskeyrrsig = server.dig("example.com", rrtype, dnssec=True, bufsize=4096)
        found_rrsigs = qdnskeyrrsig.count("RRSIG")
        if found_rrsigs == rrsig_count:
            break

        if first:
            first = False
            # Verify the zone instead of a dumb sleep
            server.zone_backup(zone, flush=True)
            server.zone_verify(zone)
        else:
            t.sleep(0.5)

        if time.monotonic() > endtime:
            break

def wait_for_dnskey_count(t, server, dnskey_count, timeout):
    endtime = time.monotonic() + timeout - 0.5
    first = True
    while True:
        qdnskeyrrsig = server.dig("example.com", "DNSKEY", dnssec=True, bufsize=4096)
        found_dnskeys = qdnskeyrrsig.count("DNSKEY")
        if found_dnskeys == dnskey_count:
            break

        if first:
            first = False
            # Verify the zone instead of a dumb sleep
            server.zone_backup(zone, flush=True)
            server.zone_verify(zone)
        else:
            t.sleep(0.5)

        if time.monotonic() > endtime:
            break

def zone_update(master, slave, zone, upd_master):
    server = master if upd_master else slave
    server.random_ddns(zone[0], allow_empty=True)

def writef(filename, contents):
    with open(filename, "w") as f:
        f.write(contents)

ON_SLAVE = random.choice([True, False])
IXFR = random.choice([True, False]) if ON_SLAVE else False

check_log("On-slave signing %s, IXFR enabled %s" % (ON_SLAVE, IXFR))

t = Test()

knot = t.server("knot")
ZONE = "example.com."
FUTURE = 55
TICK = 5
STARTUP = 10
NONSENSE = 4396

zone = t.zone(ZONE)
if ON_SLAVE:
    master = t.server("knot")
    t.link(zone, master, knot)
    if not IXFR:
        master.zones[ZONE].journal_content = "none"
else:
    master = t.server("dummy")
    t.link(zone, knot)

knot.zonefile_sync = 24 * 60 * 60

knot.dnssec(zone).enable = True
knot.dnssec(zone).manual = True
knot.dnssec(zone).offline_ksk = True
knot.dnssec(zone).alg = "ECDSAP384SHA384"
knot.dnssec(zone).dnskey_ttl = 2
knot.dnssec(zone).zone_max_ttl = 3
knot.dnssec(zone).zsk_lifetime = STARTUP + 6 * TICK # see ksk1 lifetime
knot.dnssec(zone).ksk_lifetime = NONSENSE
knot.dnssec(zone).propagation_delay = TICK - 2
knot.dnssec(zone).cds_publish = "rollover"
knot.dnssec(zone).rrsig_lifetime = 15
knot.dnssec(zone).rrsig_refresh = 6
knot.dnssec(zone).rrsig_prerefresh = 1

# needed for keymgr
knot.gen_confile()

signer = t.server("knot")
t.link(zone, signer)

# mandatory options
signer.dnssec(zone).enable = True
signer.dnssec(zone).manual = True
signer.dnssec(zone).offline_ksk = True
# needed options
signer.dnssec(zone).alg = "ECDSAP384SHA384"
# options without any effect
signer.dnssec(zone).dnskey_ttl = int(NONSENSE / 10)
signer.dnssec(zone).zone_max_ttl = NONSENSE
signer.dnssec(zone).ksk_lifetime = NONSENSE * 2
signer.dnssec(zone).propagation_delay = int(NONSENSE / 10)
signer.dnssec(zone).cds_publish = random.choice(["none", "rollover"])
signer.dnssec(zone).rrsig_lifetime = 6
signer.dnssec(zone).rrsig_refresh = 2
signer.dnssec(zone).rrsig_prerefresh = 1

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
Keymgr.run_check(knot.confile, ZONE, "pregenerate", "+20", "+" + str(FUTURE))
_, out, _ = Keymgr.run_check(knot.confile, ZONE, "generate-ksr", "+0", "+" + str(FUTURE))
writef(KSR, out)
_, out, _ = Keymgr.run_check(signer.confile, ZONE, "sign-ksr", KSR)
writef(SKR, out)

cripple_skr(SKR, SKR_BROKEN)
_, _, err = Keymgr.run_check(knot.confile, ZONE, "validate-skr", SKR_BROKEN)
if err.split()[0].casefold() != "error:":
    set_err("keymgr validate-skr")
    detail_log(err)
Keymgr.run_fail(knot.confile, ZONE, "import-skr", SKR_BROKEN)

Keymgr.run_check(knot.confile, ZONE, "import-skr", SKR)

TICK_SAFE = TICK + TICK // 2;

# run it and see if the signing and rollovers work well
t.start()
knot.zone_wait(zone)
check_zone(knot, zone, 2, 1, 1, "init")

zone_update(master, knot, zone, ON_SLAVE)
wait_for_dnskey_count(t, knot, 3, STARTUP + TICK_SAFE)
check_zone(knot, zone, 3, 2, 1, "KSK rollover: publish")

zone_update(master, knot, zone, ON_SLAVE)
wait_for_dnskey_count(t, knot, 2, TICK_SAFE * 3)
check_zone(knot, zone, 2, 1, 1, "KSK rollover: finished")

zone_update(master, knot, zone, ON_SLAVE)
wait_for_dnskey_count(t, knot, 3, TICK_SAFE * 2)
check_zone(knot, zone, 3, 1, 1, "ZSK rollover: running")

zone_update(master, knot, zone, ON_SLAVE)
wait_for_dnskey_count(t, knot, 2, TICK_SAFE * 2)
check_zone(knot, zone, 2, 1, 1, "ZSK rollover: done")

# re-generate keys, re-eschange KSR and SKR and re-import it over previous

STARTUP = 1
signer.key_set(ZONE, key_ksk2, retire=tickf(3), remove=tickf(4))
key_ksk3 = signer.key_gen(ZONE, ksk="true", created="+0", publish=tickf(1), ready=tickf(2), active=tickf(3), retire="+4h", remove="+5h")

knot.dnssec(zone).zsk_lifetime = 8 * TICK
knot.gen_confile()

KSR = KSR + "2"
SKR = SKR + "2"
Keymgr.run_check(knot.confile, ZONE, "pregenerate", "+" + str(FUTURE))
_, out, _ = Keymgr.run_check(knot.confile, ZONE, "generate-ksr", "+0", "+" + str(FUTURE))
writef(KSR, out)
_, out, _ = Keymgr.run_check(signer.confile, ZONE, "sign-ksr", KSR)
writef(SKR, out)
Keymgr.run_check(knot.confile, ZONE, "import-skr", SKR)

knot.ctl("zone-keys-load")

zone_update(master, knot, zone, ON_SLAVE)
check_zone(knot, zone, 2, 1, 1, "init2")

zone_update(master, knot, zone, ON_SLAVE)
wait_for_dnskey_count(t, knot, 3, STARTUP + TICK_SAFE)
check_zone(knot, zone, 3, 2, 1, "KSK rollover2: publish")

zone_update(master, knot, zone, ON_SLAVE)
wait_for_dnskey_count(t, knot, 2, TICK_SAFE * 3)
check_zone(knot, zone, 2, 1, 1, "KSK rollover2: finished")

zone_update(master, knot, zone, ON_SLAVE)
wait_for_dnskey_count(t, knot, 3, TICK_SAFE * 3)
check_zone(knot, zone, 3, 1, 1, "ZSK rollover2: running")

zone_update(master, knot, zone, ON_SLAVE)
wait_for_dnskey_count(t, knot, 2, TICK_SAFE * 2)
check_zone(knot, zone, 2, 1, 1, "ZSK rollover2: done")

# prepare algorithm roll-over: delete pre-generated ZSKs, arrange all the timestamps

_, out, _ = Keymgr.run_check(knot.confile, ZONE, "list")
for line in out.split('\n'):
    if len(line) > 0 and line.split()[-1] == "remove=0": # only one key with this property
        last_zsk = line.split()[0]

algtick = 5
now = int(time.time())
preactive = now + algtick
publish = preactive + algtick
postactive = publish + algtick
remove = postactive + algtick

key_ksk4 = signer.key_gen(ZONE, ksk="true", algorithm="ECDSAP256SHA256", created="+0", pre_active=str(preactive), publish=str(publish), ready=str(publish), active=str(postactive))
key_zsk2 = knot.key_gen(ZONE, ksk="false", algorithm="ECDSAP256SHA256", created="+0", pre_active=str(preactive), publish=str(publish), active=str(postactive))
signer.key_set(ZONE, key_ksk3, post_active=str(postactive), remove=str(remove))
knot.key_set(ZONE, last_zsk, post_active=str(postactive), remove=str(remove))

KSR = KSR + "3"
SKR = SKR + "3"
_, out, _ = Keymgr.run_check(knot.confile, ZONE, "generate-ksr", "+0", str(remove + 1))
writef(KSR, out)
_, out, _ = Keymgr.run_check(signer.confile, ZONE, "sign-ksr", KSR)
writef(SKR, out)
Keymgr.run_check(knot.confile, ZONE, "import-skr", SKR)
knot.ctl("zone-keys-load")

zone_update(master, knot, zone, ON_SLAVE)
wait_for_rrsig_count(t, knot, "SOA", 2, algtick + 2)
check_zone(knot, zone, 2, 1, 2, "alg roll: pre-active")

zone_update(master, knot, zone, ON_SLAVE)
wait_for_dnskey_count(t, knot, 4, algtick + 2)
check_zone(knot, zone, 4, 2, 2, "alg roll: published")

zone_update(master, knot, zone, ON_SLAVE)
wait_for_dnskey_count(t, knot, 2, algtick + 2)
check_zone(knot, zone, 2, 2, 2, "alg roll: post-active")

zone_update(master, knot, zone, ON_SLAVE)
wait_for_rrsig_count(t, knot, "SOA", 1, algtick + 2)
check_zone(knot, zone, 2, 1, 1, "alg roll: finished")

t.end()
