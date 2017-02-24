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
    "stss_zsk":             True,
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

# install KASP db
shutil.copytree(os.path.join(t.data_dir, "keys"), knot.keydir)
keys_archive = os.path.join(t.data_dir, "keys_priv.tgz")
with tarfile.open(keys_archive, "r:*") as tar:
    tar.extractall(knot.keydir)

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

t.start()

for zone in [zone for zone in zones if TEST_CASES[zone.name.rstrip(".")]]:
    knot.zone_wait(zone)

for zone, valid in TEST_CASES.items():
    expected_rcode = "NOERROR" if valid else "SERVFAIL"
    knot.dig(zone, "SOA").check(rcode=expected_rcode)

t.end()
