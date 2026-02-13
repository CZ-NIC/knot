#!/usr/bin/env python3

'''Check that incremental ZONEMD doesnt depend on how incrementally it arose.'''

import random

from dnstest.test import Test
from dnstest.utils import *

def some_ddns(server, z, i):
    #server.random_ddns(z, allow_empty=False)
    up = server.update(z)
    up.add("xxx%d" % i, 3600, "AAAA", "1::56")
    if i > 1:
        up.delete("xxx%d" % (i - 2), "AAAA")
    up.send("NOERROR")

t = Test()

master = t.server("knot")
slave = t.server("knot")

zone = t.zone_rnd(1, records=3200, dnssec=False)
t.link(zone, master, slave)

master.conf_zone(zone).zonemd_generate = "zonemd-sha384"
master.conf_zone(zone).zonemd_scheme = "tree3"
slave.conf_zone(zone).zonemd_verify = True
slave.conf_zone(zone).zonefile_sync = -1

t.start()
serial = slave.zone_wait(zone)

master.ctl("zone-flush", wait=True) # for random_ddns() with knsupdate to have proper zone file format

some_ddns(master, zone, -1)
serial = slave.zone_wait(zone, serial)

slave.ctl("zone-freeze")
for i in range(4):
    some_ddns(master, zone, i)
slave.ctl("zone-thaw")

serial = slave.zone_wait(zone, serial + 3)

slave.ctl("-f zone-purge +journal +timers " + zone[0].name)
slave.stop()
slave.start()

serial = slave.zone_wait(zone, serial, equal=True, greater=False)

t.end()
