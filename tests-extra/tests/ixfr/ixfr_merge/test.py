#!/usr/bin/env python3

'''Test for chain IXFR with middle man being frozen'''

from dnstest.test import Test
from dnstest.utils import *

t = Test()

s1 = t.server("knot")
s2 = t.server("knot")
s3 = t.server("bind")
zone = t.zone("dk.", storage=".")

t.link(zone, s1, s2)
t.link(zone, s2, s3)

s1.dnssec(zone).enable = True
s1.dnssec(zone).nsec3 = True
s1.dnssec(zone).nsec3_opt_out = True

t.start()

serials_init = s3.zone_wait(zone)

#s2.ctl("zone-freeze -b")

ts = 1
for i in range(3):
    up = s1.update(zone)
    up.delete("timestamp._zoneage.dk.", "TXT")
    up.add("timestamp._zoneage.dk.", "86400", "TXT", str(ts))
    up.send("NOERROR")
    ts = ts + 1

#s2.ctl("zone-thaw")

t.sleep(1)

if s2.log_search("incomplete history") or s2.log_search("fallback to AXFR"):
    set_err("IXFR merge error")

if s3.log_search("no such record in zone found") or s3.log_search("fallback to AXFR"):
    set_err("IXFR ERROR")

t.end()
