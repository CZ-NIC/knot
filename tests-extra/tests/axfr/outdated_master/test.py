#!/usr/bin/env python3

'''Test of treating outdated master'''

from dnstest.test import Test
from dnstest.utils import *

t = Test()

master = t.server("knot")
slave = t.server("knot")
zones = t.zone_rnd(5)

t.link(zones, master, slave)

master.zonefile_sync = -1

t.start()
serial = slave.zones_wait(zones)

for z in zones:
    up = master.update(z)
    up.add("abc", 3600, "A", "1.2.3.4")
    up.send()
slave.zones_wait(zones, serial)

slave.stop()
master.ctl("zone-purge -f +journal --")
master.stop()

slave.clean(zone=False, timers=True)
master.start()
master.zones_wait(zones)
slave.start()
slave.zones_wait(zones, serial)

t.sleep(4)
cnt = slave.log_search_count("remote is outdated")
if cnt > 3 * len(zones):
    set_err("requestor throttling")

t.end()
