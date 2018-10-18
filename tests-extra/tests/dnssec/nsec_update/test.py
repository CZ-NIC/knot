#!/usr/bin/env python3

'''Test for NSEC and NSEC3 fix after zone update'''

from dnstest.utils import *
from dnstest.test import Test
import random

t = Test()

master = t.server("knot")
slave = t.server("knot")
zones = t.zone_rnd(5, dnssec=False, records=30) + t.zone("records.")

t.link(zones, master, slave)

master.disable_notify = True
slave.disable_notify = True

for zone in zones:
    master.dnssec(zone).enable = True
    master.dnssec(zone).nsec3 = random.choice([True, False])
    master.dnssec(zone).nsec3_iters = 2
    master.dnssec(zone).nsec3_salt_len = 8

t.start()
t.sleep(4)
slave.ctl("zone-refresh")

slave.zones_wait(zones)

# initial convenience check
t.xfr_diff(master, slave, zones)

# update master
master.flush()
t.sleep(2)
for zone in zones:
    master.random_ddns(zone)
t.sleep(4) # zones_wait fails if an empty update is generated

after_update = master.zones_wait(zones)

# sync slave with current master's state
slave.ctl("zone-refresh")
t.sleep(5)

slave.zones_wait(zones, after_update, equal=True, greater=False)

# re-sign master and check that the re-sign made nothing
master.ctl("zone-sign")
master.zones_wait(zones, after_update, equal=False, greater=True)

t.xfr_diff(master, slave, zones, no_rrsig_rdata=True)

t.end()
