#!/usr/bin/env python3
"""
Validate ZSK and KSK constrains checks.
"""

import shutil
import tarfile
import os.path

import dnstest.zonefile
from dnstest.test import Test

TEST_CASES = {
    "rsa":                  True,
    "rsa_ecdsa":            True,
    "rsa_now_ecdsa_future": True,
    "rsa_ecdsa_roll":       True,
    "stss_ksk":             True,
#   "stss_zsk":             True, # No longer supported.
    "stss_two_ksk":         True,
    "stss_rsa256_rsa512":   True,
    "rsa_split_ecdsa_stss": True,

    "rsa_future_all":       False,
    "rsa_future_publish":   False,
    "rsa_future_active":    False,
    "rsa_inactive_zsk":     False,
    "rsa_no_zsk":           False,
}

t = Test()

knot = t.server("knot")

# setup zones
zones = []
for zone_name in TEST_CASES:
    zone = dnstest.zonefile.ZoneFile(t.zones_dir)
    zone.set_name(zone_name)
    zone.gen_file(dnssec=False, nsec3=False, records=5)
    zones.append(zone)

t.link(zones, knot)

for zone in zones:
    knot.dnssec(zone).enable = True
    knot.dnssec(zone).manual = True

INF="9999999999"
GEN="1450000000"
PAST="189000000"
FUTU="2711000000"

## Valid scenarios

# KSK+ZSK, simple
knot.key_gen("rsa",                  ksk="true",  created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF)
knot.key_gen("rsa",                  ksk="false", created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF)
# KSK+ZSK, two algorithms
knot.key_gen("rsa_ecdsa",            ksk="false", created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF)
knot.key_gen("rsa_ecdsa",            ksk="true",  created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF)
knot.key_gen("rsa_ecdsa",            ksk="false", created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF)
knot.key_gen("rsa_ecdsa",            ksk="true",  created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF)
# KSK+ZSK: RSA enabled, ECDSA in future
knot.key_gen("rsa_now_ecdsa_future", ksk="false", created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF)
knot.key_gen("rsa_now_ecdsa_future", ksk="false", created=GEN, publish=FUTU, ready=FUTU, active=FUTU, retire=INF, remove=INF)
knot.key_gen("rsa_now_ecdsa_future", ksk="true",  created=GEN, publish=FUTU, ready=FUTU, active=FUTU, retire=INF, remove=INF)
knot.key_gen("rsa_now_ecdsa_future", ksk="true",  created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF)
# KSK+ZSK, algorithm rollover (signatures pre-published)
knot.key_gen("rsa_ecdsa_roll",       ksk="false", created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF)
knot.key_gen("rsa_ecdsa_roll",       ksk="true",  created=GEN, publish=FUTU, ready=PAST, active=PAST, retire=INF, remove=INF)
knot.key_gen("rsa_ecdsa_roll",       ksk="true",  created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF)
knot.key_gen("rsa_ecdsa_roll",       ksk="false", created=GEN, publish=FUTU, ready=PAST, active=PAST, retire=INF, remove=INF)
# STSS: KSK only
knot.key_gen("stss_ksk",             ksk="true",  created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF)
# STSS: two KSKs
knot.key_gen("stss_two_ksk",         ksk="true",  created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF)
knot.key_gen("stss_two_ksk",         ksk="true",  created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF)
# STSS: different algorithms
knot.key_gen("stss_rsa256_rsa512",   ksk="true",  created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF)
knot.key_gen("stss_rsa256_rsa512",   ksk="false", created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF)
# KSK+ZSK for RSA, STSS for ECDSA
knot.key_gen("rsa_split_ecdsa_stss", ksk="true",  created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF)
knot.key_gen("rsa_split_ecdsa_stss", ksk="false", created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF)
knot.key_gen("rsa_split_ecdsa_stss", ksk="true",  created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF)

## Invalid scenarios

# no key for now
knot.key_gen("rsa_future_all",       ksk="false", created=GEN, publish=FUTU, ready=FUTU, active=FUTU, retire=INF, remove=INF)
knot.key_gen("rsa_future_all",       ksk="true",  created=GEN, publish=FUTU, ready=FUTU, active=FUTU, retire=INF, remove=INF)
# key active, not published
knot.key_gen("rsa_future_publish",   ksk="false", created=GEN, publish=FUTU, ready=PAST, active=PAST, retire=INF, remove=INF)
knot.key_gen("rsa_future_publish",   ksk="true",  created=GEN, publish=FUTU, ready=PAST, active=PAST, retire=INF, remove=INF)
# key published, not active
knot.key_gen("rsa_future_active",    ksk="true",  created=GEN, publish=PAST, ready=FUTU, active=FUTU, retire=INF, remove=INF)
knot.key_gen("rsa_future_active",    ksk="false", created=GEN, publish=PAST, ready=FUTU, active=FUTU, retire=INF, remove=INF)
# no signatures for KSK
knot.key_gen("rsa_inactive_zsk",     ksk="false", created=GEN, publish=PAST, ready=FUTU, active=FUTU, retire=INF, remove=INF)
knot.key_gen("rsa_inactive_zsk",     ksk="true",  created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF)
# no signatures for ZSK
knot.key_gen("rsa_no_zsk",           ksk="false", created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF)
knot.key_gen("rsa_no_zsk",           ksk="true",  created=GEN, publish=FUTU, ready=FUTU, active=FUTU, retire=INF, remove=INF)

t.start()

for zone in [zone for zone in zones if TEST_CASES[zone.name.rstrip(".")]]:
    knot.zone_wait(zone)

for zone, valid in TEST_CASES.items():
    expected_rcode = "NOERROR" if valid else "SERVFAIL"
    knot.dig(zone, "SOA").check(rcode=expected_rcode)

t.end()
