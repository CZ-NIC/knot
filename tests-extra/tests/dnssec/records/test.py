#!/usr/bin/env python3

'''Test for signing a zone with weird records.'''

from dnstest.utils import *
from dnstest.test import Test

t = Test()

master = t.server("knot")
zone = t.zone("records.")
t.link(zone, master)
master.dnssec(zone).enable = True

t.start()

master.zone_wait(zone)

t.sleep(1)
master.flush(zone)
t.sleep(1)

# Verify signed zone file.
master.zone_verify(zone)

t.stop()
