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
knot.key_gen("rsa",                  algorithm="8",  ksk="true",  created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF, size="1024")
knot.key_gen("rsa",                  algorithm="8",  ksk="false", created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF, size="1024")
# KSK+ZSK, two algorithms
knot.key_gen("rsa_ecdsa",            algorithm="8",  ksk="false", created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF, size="1024")
knot.key_gen("rsa_ecdsa",            algorithm="8",  ksk="true",  created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF, size="1024")
knot.key_gen("rsa_ecdsa",            algorithm="13", ksk="false", created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF, size="256")
knot.key_gen("rsa_ecdsa",            algorithm="13", ksk="true",  created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF, size="256")
# KSK+ZSK: RSA enabled, ECDSA in future
knot.key_gen("rsa_now_ecdsa_future", algorithm="8",  ksk="false", created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF, size="1024")
knot.key_gen("rsa_now_ecdsa_future", algorithm="13", ksk="false", created=GEN, publish=FUTU, ready=FUTU, active=FUTU, retire=INF, remove=INF, size="256")
knot.key_gen("rsa_now_ecdsa_future", algorithm="13", ksk="true",  created=GEN, publish=FUTU, ready=FUTU, active=FUTU, retire=INF, remove=INF, size="256")
knot.key_gen("rsa_now_ecdsa_future", algorithm="8",  ksk="true",  created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF, size="1024")
# KSK+ZSK, algorithm rollover (signatures pre-published)
knot.key_gen("rsa_ecdsa_roll",       algorithm="8",  ksk="false", created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF, size="1024")
knot.key_gen("rsa_ecdsa_roll",       algorithm="13", ksk="true",  created=GEN, publish=FUTU, pre_active=PAST, active=FUTU, retire=INF, remove=INF, size="256")
knot.key_gen("rsa_ecdsa_roll",       algorithm="8",  ksk="true",  created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF, size="1024")
knot.key_gen("rsa_ecdsa_roll",       algorithm="13", ksk="false", created=GEN, publish=FUTU, pre_active=PAST, active=FUTU, retire=INF, remove=INF, size="256")
# STSS: KSK only
knot.key_gen("stss_ksk",             algorithm="8",  ksk="true", zsk="true", created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF, size="1024")
# STSS: two KSKs
knot.key_gen("stss_two_ksk",         algorithm="8",  ksk="true", zsk="true", created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF, size="1024")
knot.key_gen("stss_two_ksk",         algorithm="8",  ksk="true", zsk="true", created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF, size="1024")
# STSS: different algorithms
knot.key_gen("stss_rsa256_rsa512",   algorithm="8",  ksk="true", zsk="true", created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF, size="1024")
knot.key_gen("stss_rsa256_rsa512",   algorithm="10", ksk="true", zsk="true", created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF, size="1024", sep="false")
# KSK+ZSK for RSA, STSS for ECDSA
knot.key_gen("rsa_split_ecdsa_stss", algorithm="8",  ksk="true",  created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF, size="1024")
knot.key_gen("rsa_split_ecdsa_stss", algorithm="8",  ksk="false", created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF, size="1024")
knot.key_gen("rsa_split_ecdsa_stss", algorithm="13", ksk="true", zsk="true", created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF, size="256")

## Invalid scenarios

# no key for now
knot.key_gen("rsa_future_all",       algorithm="8",  ksk="false", created=GEN, publish=FUTU, ready=FUTU, active=FUTU, retire=INF, remove=INF, size="1024")
knot.key_gen("rsa_future_all",       algorithm="8",  ksk="true",  created=GEN, publish=FUTU, ready=FUTU, active=FUTU, retire=INF, remove=INF, size="1024")
# key active, not published
knot.key_gen("rsa_future_publish",   algorithm="8",  ksk="false", created=GEN, publish=FUTU, pre_active=PAST, active=FUTU, retire=INF, remove=INF, size="1024")
knot.key_gen("rsa_future_publish",   algorithm="8",  ksk="true",  created=GEN, publish=FUTU, pre_active=PAST, active=FUTU, retire=INF, remove=INF, size="1024")
# key published, not active
knot.key_gen("rsa_future_active",    algorithm="8",  ksk="true",  created=GEN, publish=PAST, ready=FUTU, active=FUTU, retire=INF, remove=INF, size="1024")
knot.key_gen("rsa_future_active",    algorithm="8",  ksk="false", created=GEN, publish=PAST, ready=FUTU, active=FUTU, retire=INF, remove=INF, size="1024")
# no signatures for KSK
knot.key_gen("rsa_inactive_zsk",     algorithm="8",  ksk="false", created=GEN, publish=PAST, ready=FUTU, active=FUTU, retire=INF, remove=INF, size="1024")
knot.key_gen("rsa_inactive_zsk",     algorithm="8",  ksk="true",  created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF, size="1024")
# no signatures for ZSK
knot.key_gen("rsa_no_zsk",           algorithm="8",  ksk="false", created=GEN, publish=PAST, ready=PAST, active=PAST, retire=INF, remove=INF, size="1024")
knot.key_gen("rsa_no_zsk",           algorithm="8",  ksk="true",  created=GEN, publish=FUTU, ready=FUTU, active=FUTU, retire=INF, remove=INF, size="1024")

t.start()

for zone in [zone for zone in zones if TEST_CASES[zone.name.rstrip(".")]]:
    knot.zone_wait(zone)

for zone, valid in TEST_CASES.items():
    expected_rcode = "NOERROR" if valid else "SERVFAIL"
    knot.dig(zone, "SOA").check(rcode=expected_rcode)

t.end()
