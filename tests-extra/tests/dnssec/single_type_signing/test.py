#!/usr/bin/env python3
"""
DNSSEC Single-Type Signing Scheme, RFC 6781
"""
from dnstest.utils import *
from dnstest.test import Test

t = Test()

knot = t.server("knot")
zones = t.zone_rnd(5, dnssec=False, records=10)
t.link(zones, knot)
t.start()

# one KSK
knot.gen_key(zones[0], ksk=True, alg="RSASHA256", key_len="512")

# one ZSK
knot.gen_key(zones[1], ksk=False, alg="RSASHA512", key_len="1024")

# multiple KSKs
knot.gen_key(zones[2], ksk=True, alg="RSASHA512", key_len="1024")
knot.gen_key(zones[2], ksk=True, alg="RSASHA256", key_len="512")

# different algorithms: KSK+ZSK pair, one ZSK
knot.gen_key(zones[3], ksk=True, alg="RSASHA256", key_len="1024")
knot.gen_key(zones[3], ksk=False, alg="RSASHA256", key_len="1024")
knot.gen_key(zones[3], ksk=False, alg="RSASHA512", key_len="1024")

for zone in zones[:-1]:
    knot.dnssec(zone).enable = True
    knot.dnssec(zone).manual = True

# enable automatic Single-Type signing scheme on the last zone
knot.dnssec(zones[-1]).enable = True
knot.dnssec(zones[-1]).single_type_signing = True

knot.gen_confile()
knot.reload()
t.sleep(2)
knot.flush()
t.sleep(2)
knot.stop()

for zone in zones:
    knot.zone_verify(zone)

t.end()
