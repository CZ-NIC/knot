#!/usr/bin/env python3
"""
Validate ZSK and KSK constrains checks.
"""

import tarfile
import os.path

import dnstest.zonefile
from dnstest.test import Test

TEST_CASES = {
    # valid cases
    "rsa_ok":             True,
    "rsa_ecdsa_ok":       True,
    "rsa_ecdsa_roll_ok":  True,
    # valid single-type signing
    "rsa_stss_ksk":       True,
    "rsa_stss_zsk":       True,
    # invalid cases
    "rsa_future_all":     False,
    "rsa_future_publish": False,
    "rsa_future_active":  False,
    "rsa_inactive_zsk":   False,
    "rsa_no_zsk":         False,
    "rsa_ecdsa_ksk_only": False,
    "rsa256_rsa512":      False,
}

t = Test()

knot = t.server("knot")
knot.dnssec_enable = True

# setup keys

keys_archive = os.path.join(t.data_dir, "keys.tgz")
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

t.start()

for zone, valid in TEST_CASES.items():
    expected_rcode = "NOERROR" if valid else "SERVFAIL"
    knot.dig(zone, "SOA").check(rcode=expected_rcode)

t.end()
