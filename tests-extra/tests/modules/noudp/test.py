#!/usr/bin/env python3

''' Check 'dnstap' query module functionality. '''

import os
import re
import dns.flags
from dnstest.test import Test
from dnstest.module import ModNoudp
from dnstest.utils import *

t = Test()
ModNoudp.check()

# Initialize server configuration
knot = t.server("knot")
knot.udp_workers = 1
zone_return_tc = t.zone("example.")
zone_return_notc = t.zone("flags.")
zone_50_50 = t.zone(".")

t.link(zone_return_tc, knot)
t.link(zone_return_notc, knot)
t.link(zone_50_50, knot)

# Configure 'noudp' module for all queries (default).
knot.add_module(zone_return_tc,   ModNoudp())
knot.add_module(zone_return_notc, ModNoudp(rate=1))
knot.add_module(zone_50_50,       ModNoudp(deny_mode=True, rate=2))

t.start()

for _ in range(0, 10):
    resp = knot.dig("ns1.a.example.", "A", udp=True)
    resp.check(flags="TC")

for _ in range(0, 10):
    resp = knot.dig("dns1.flags", "A", udp=True)
    resp.check(noflags="TC")

# Sometimes, this fail and I'm not sure why
for _ in range(0, 5):
    resp = knot.dig("ac.", "A", udp=True)
    resp.check(noflags="TC")
    
    resp = knot.dig("dnsc.ad.", "A", udp=True)
    resp.check(flags="TC")

knot.stop()
t.end()
