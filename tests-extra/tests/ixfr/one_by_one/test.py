#!/usr/bin/env python3

'''Test for IXFR one-by-one'''

import os
import random
from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")
zones = t.zone_rnd(5, records=50)

t.link(zones, master, slave, ixfr=True)

slave.ixfr_by_one = "on"

t.start()

serials = [0]*5
serials[0] = master.zones_wait(zones)
slave.zones_wait(zones)

slave.ctl("zone-freeze")

for i in range(4):
    for zone in zones:
        master.update_zonefile(zone, random=True)
    master.reload()
    serials[i+1] = master.zones_wait(zones, serials[i])

slave.zones_wait(zones, serials[0], equal=True, greater=False) # just check that correctly frozen
slave.ctl("zone-thaw")
slave.zones_wait(zones, serials[3])

for i in range(4):
    t.xfr_diff(master, slave, zones, serials[i])

t.end()
