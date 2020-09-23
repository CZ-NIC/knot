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
zone = t.zone("example.")
t.link(zone, knot)

# Configure 'noudp' module for all queries (default).
knot.add_module(None, ModNoudp(deny_mode=False, rate=0))
#knot.add_module(zone, ModNoudp(deny_mode=True, rate=0))


t.start()

resp = knot.dig("ns1.a.example.", "A")
resp.check(flags="TC")

knot.stop()
t.end()
