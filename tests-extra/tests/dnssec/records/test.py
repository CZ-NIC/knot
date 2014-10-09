#!/usr/bin/env python3

'''Test for signing a zone with wierd records.'''

from dnstest.utils import *
from dnstest.test import Test

t = Test()

master = t.server("knot")
zone = t.zone("records.")
t.link(zone, master)

# Enable autosigning.
master.dnssec_enable = True
master.gen_key(zone, ksk=True, alg="RSASHA1")
master.gen_key(zone, alg="RSASHA1")
master.gen_confile()

t.start()

master.zone_wait(zone)

master.flush()

# Verify signed zone file.
master.zone_verify(zone)

t.stop()
