#!/usr/bin/env python3

'''Purge and replan on slave.'''

import random
from dnstest.test import Test
from dnstest.utils import *

#DNSSEC = random.choice([False, True])

t = Test()

master = t.server("knot")
slave = t.server("knot")
zone = t.zone_rnd(1, dnssec=False, records=10)
t.link(zone, master, slave)
ZONE = zone[0].name

t.start()

serial = slave.zones_wait(zone)

slave.ctl("zone-freeze " + ZONE, wait=True)

slave.ctl("-f zone-purge " + ZONE, wait=True)

slave.ctl("zone-reload " + ZONE, wait=True)

slave.ctl("zone-thaw " + ZONE)
slave.zones_wait(zone, serial, equal=True)

t.end()
