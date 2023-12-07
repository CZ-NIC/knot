#!/usr/bin/env python3

"""

"""

import random
from dnstest.utils import *
from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")
zones = t.zone("example.com.")
t.link(zones, master, slave)

master.zonefile_sync = -1
master.zonefile_load = "difference"
for z in zones:
    master.zones[z.name].journal_content = "changes"
    master.dnssec(z).enable = True

t.start()

serials = slave.zones_wait(zones)

for z in zones:
    master.zones[z.name].zfile.update_soa()
    master.zones[z.name].zfile.append_rndTXT("a")
master.ctl("zone-reload")

serials = slave.zones_wait(zones, serials)

master.stop()
master.start()
master.zones_wait(zones, serials, equal=True, greater=False)
slave.ctl("zone-refresh")
t.sleep(2)
slave.zones_wait(zones, serials, equal=True, greater=False)




t.end()
