#!/usr/bin/env python3

''' Check 'dnstap' query module functionality. '''

import os
import re
import dns.flags
from dnstest.test import Test
from dnstest.module import ModNoudp
from dnstest.utils import *

t = Test(stress=False)

ModNoudp.check()

knot = t.server("knot")
knot.udp_workers = 1

zone_tc = t.zone("example.")
zone_notc = t.zone("flags.")
zone_50_50 = t.zone(".")
zones = zone_tc + zone_notc + zone_50_50

t.link(zones, knot)

knot.add_module(zone_tc,    ModNoudp())
knot.add_module(zone_notc,  ModNoudp(allow_rate=1))
knot.add_module(zone_50_50, ModNoudp(trunc_rate=2))

t.start()

for _ in range(0, 10):
    resp = knot.dig(zone_tc[0].name, "SOA", udp=True)
    resp.check(flags="TC")

for _ in range(0, 10):
    resp = knot.dig(zone_notc[0].name, "SOA", udp=True)
    resp.check(noflags="TC")

for _ in range(0, 5):
    resp = knot.dig(zone_50_50[0].name, "SOA", udp=True)
    resp.check(noflags="TC")

    resp = knot.dig(zone_50_50[0].name, "SOA", udp=True)
    resp.check(flags="TC")

t.end()
