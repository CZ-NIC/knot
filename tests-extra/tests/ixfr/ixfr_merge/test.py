#!/usr/bin/env python3

'''Test for chain IXFR with middle man being frozen'''

from dnstest.test import Test
from dnstest.utils import *

t = Test()

s1 = t.server("knot")
s2 = t.server("knot")
s3 = t.server("knot")
zones = t.zone("example.com.") #t.zone_rnd(5)

t.link(zones, s1, s2, ixfr=True)
t.link(zones, s2, s3, ixfr=True)

for zone in zones:
    s1.dnssec(zone).enable = True

t.start()

serials_init = s3.zones_wait(zones)

s2.ctl("zone-freeze")
t.sleep(1)

s1.ctl("zone-sign")
t.sleep(2)
s1.ctl("zone-sign")
t.sleep(2)

s2.ctl("zone-thaw")

s3.zones_wait(zones, serials_init)

if s2.log_search("incomplete history") or s2.log_search("fallback to AXFR"):
    set_err("IXFR merge error")

if s3.log_search("no such record in zone found") or s3.log_search("fallback to AXFR"):
    set_err("IXFR ERROR")

t.end()
