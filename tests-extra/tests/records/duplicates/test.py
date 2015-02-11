#!/usr/bin/env python3

''' Test for loading records with RDATA and owners differing only in case '''

from dnstest.utils import *
from dnstest.test import Test

t = Test()

knot = t.server("knot")
zone = t.zone("duplicates.", storage=".")
t.link(zone, knot)

t.start()

knot.zones_wait(zone)

# Request AXFR from Knot
resp = knot.dig("duplicates.", "AXFR")

# If Knot has not properly handled the case, there will be some redundant record
count = 0
for msg in resp.resp:
	count += len(msg.answer)

compare(count, 6, "AXFR record count")

t.end()
