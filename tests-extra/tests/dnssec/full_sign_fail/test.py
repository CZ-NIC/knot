#!/usr/bin/env python3

'''Test failed zone sign with incremental still working.'''

from dnstest.test import Test
from dnstest.utils import *

t = Test()

server = t.server("knot")
zone = t.zone_rnd(1, records=40, dnssec=False)

t.link(zone, server)

for z in zone:
    server.dnssec(z).enable = True
    server.dnssec(z).rrsig_lifetime = 20
    server.dnssec(z).rrsig_refresh = 10
    server.dnssec(z).rrsig_prerefresh = 4

server.journal_max_usage = 128*1024

t.start()

server.zone_wait(zone)

for i in range(100):
    up = server.update(zone)
    for j in range(10):
        up.add("abc%dxyz%d" % (i, j), 3600, "A", "1.2.3.4")
    up.send()
    t.sleep(0.5)
    if server.log_search("enough space"):
        break

up = server.update(zone)
up.add("final", 3600, "A", "1.2.3.4")
up.send()

last_fail_logs = server.log_search_count("signing had failed")

if last_fail_logs < 1 or last_fail_logs > 3:
    set_err("SIGN FAILED WARNING (%d)" % last_fail_logs)

for z in zone:
    server.zone_verify(z) # this should still pass since rrsig-refresh is comfortably high

t.end()
