#!/usr/bin/env python3

'''Test of difference-no-serial on slave. '''

from dnstest.test import Test
from dnstest.utils import *

t = Test()

master = t.server("knot")
slave = t.server("knot")

zone = t.zone_rnd(1, records=300)
t.link(zone, master, slave)

slave.conf_zone(zone).journal_content = "all"
slave.conf_zone(zone).zonefile_load = "difference-no-serial"
slave.conf_zone(zone).journal_max_depth = 3
slave.conf_zone(zone).zonefile_sync = "-1"

t.start()

serial = slave.zone_wait(zone)
slave.ctl("-f zone-flush")
for i in range(4):
    master.random_ddns(zone, allow_empty=False)
    serial = slave.zone_wait(zone, serial)

slave.stop()
t.sleep(2)
slave.start()

slave.zone_wait(zone)
slave.ctl("zone-refresh", wait=True)

if slave.log_search("remote is outdated"):
    set_err("OUTDATED MASTER")

t.xfr_diff(master, slave, zone)

t.end()
