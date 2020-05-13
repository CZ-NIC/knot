#!/usr/bin/env python3

'''Test for chain IXFR with middle man being frozen'''

from dnstest.test import Test
from dnstest.utils import *

t = Test()

s1 = t.server("knot")
s2 = t.server("knot")
s3 = t.server("knot")
zones = t.zone_rnd(5)

t.link(zones, s1, s2, ixfr=True)
t.link(zones, s2, s3, ixfr=True)

if not s1.valgrind:
    s2.tcp_remote_io_timeout = 8000
    s3.tcp_remote_io_timeout = 8000
else:
    s1.tcp_remote_io_timeout = 45000
    s2.tcp_remote_io_timeout = 45000
    s3.tcp_remote_io_timeout = 45000
    s1.ctl_params_append = ["-t", "45"]
    s2.ctl_params_append = ["-t", "45"]
    s3.ctl_params_append = ["-t", "45"]

for zone in zones:
    s1.dnssec(zone).enable = True

t.start()

serials_init = s3.zones_wait(zones)

s2.ctl("zone-freeze", wait=True)

s1.ctl("zone-sign", wait=True)
s1.ctl("zone-sign", wait=True)

s2.ctl("zone-thaw", wait=True)

s3.zones_wait(zones, serials_init)

if s2.log_search("incomplete history") or s2.log_search("fallback to AXFR"):
    set_err("IXFR merge error")

if s3.log_search("no such record in zone found") or s3.log_search("fallback to AXFR"):
    set_err("IXFR ERROR")

t.end()
