#!/usr/bin/env python3

"""
AXFR/IXFR jitter.
"""

from dnstest.test import Test
from dnstest.utils import *
from collections import Counter

t = Test()

zones = t.zone_rnd(20, records=1, dnssec=False)
for z in zones:
    z.update_soa(serial=1, refresh=25, retry=10, expire=3600)

master = t.server("knot")
slave = t.server("knot")

t.link(zones, master, slave)

master.disable_notify = True
slave.conf_zone(zones).refresh_jitter = 12

def wait_for_any(server, zns, rrtype, callback, arg):
    for i in range(100):
        t.sleep(0.3)
        for z in zns:
            resp = server.dig(z.name, rrtype)
            if callback(resp, arg):
                return

def has_serial(response, serial):
    return response.soa_serial() == serial

def check_jitter(server, zns, old_serial, msg):
    new_serial = old_serial + 1
    threshold = len(zns) * 20 / 100
    serials = server.zones_wait(zns)
    counts = dict(Counter(serials.values()))
    detail_log(str(counts))
    isset(counts[old_serial] > threshold, "%s: some old serials" % msg)
    isset(counts[new_serial] > threshold, "%s: some new serials" % msg)
    compare(counts[old_serial] + counts[new_serial], len(zns), "%s: no other serials" % msg)

t.start()

slave.zones_wait(zones)
for z in zones:
    master.random_ddns(z, allow_empty=False)
wait_for_any(slave, zones, "SOA", has_serial, 2)
t.sleep(4)
check_jitter(slave, zones, 1, "SOA timer")

slave.ctl("zone-refresh") # reset the refresh timers to equal again

master.disable_notify = False
master.gen_confile()
master.reload()
slave.gen_confile()
slave.reload()

for z in zones:
    master.random_ddns(z, allow_empty=False)
wait_for_any(slave, zones, "SOA", has_serial, 3)
t.sleep(6)
check_jitter(slave, zones, 2, "NOTIFY reaction")

t.stop()
