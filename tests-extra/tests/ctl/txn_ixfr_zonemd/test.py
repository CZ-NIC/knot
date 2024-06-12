#!/usr/bin/env python3

'''Test IXFR with undergoing CTL zone transaction.'''

import os
import random
from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")
zones = t.zone_rnd(1, records=50)
ZONE = zones[0].name

t.link(zones, master, slave, ixfr=True)

slave.zonemd_generate = "zonemd-sha512"

t.start()

serials = slave.zones_wait(zones)

slave.ctl("zone-begin " + ZONE)
slave.ctl("zone-set " + ZONE + " jdoiwjeodjewo 3600 A 1.2.3.4")

master.random_ddns(zones, allow_empty=False)
t.sleep(2)

slave.ctl("zone-commit " + ZONE)

slave.zones_wait(zones, serials)

t.end()
