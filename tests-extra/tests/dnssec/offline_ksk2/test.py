#!/usr/bin/env python3

"""
Test of offline signing with unset RRSIG refresh.
"""

import random

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

    server.zone_backup(zone, flush=True)
    server.zone_verify(zone)

def writef(filename, contents):
    with open(filename, "w") as f:
        f.write(contents)

FUTURE = 3600 * 24 * 730

t = Test()

knot = t.server("knot")
ZONE = "example.com."

zone = t.zone(ZONE)
t.link(zone, knot)

knot.zonefile_sync = 24 * 60 * 60

# ZSK side
knot.dnssec(zone).enable = True
knot.dnssec(zone).manual = True
knot.dnssec(zone).offline_ksk = True
knot.dnssec(zone).dnskey_ttl = 3600
knot.dnssec(zone).zone_max_ttl = 3600
# optional
knot.dnssec(zone).zsk_lifetime = 3600 * 24 * 365

# needed for keymgr
knot.gen_confile()

signer = t.server("knot")
t.link(zone, signer)

# KSK side
signer.dnssec(zone).enable = True
signer.dnssec(zone).manual = True
signer.dnssec(zone).offline_ksk = True
#signer.dnssec(zone).rrsig_refresh = 3600 * 24 * 40 # unset
# optional
signer.dnssec(zone).rrsig_lifetime = 3600 * 24 * 160

# needed for keymgr
signer.gen_confile()

# generate keys, including manual KSK rollover on the beginning
key_ksk1 = signer.key_gen(ZONE, ksk="true", created="+0", publish="+0", ready="+0", active="+0")
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

Keymgr.run_check(knot.confile, ZONE, "import-skr", SKR)

# run it and see if the signing works well
t.start()
knot.zone_wait(zone)
check_zone(knot, zone, 2, 1, 1, "init")

t.end()
