#!/usr/bin/env python3

'''Test for NSEC and NSEC3 fix after zone update (ddns, ixfr)'''

from dnstest.utils import *
from dnstest.test import Test
import random

t = Test()

master0 = t.server("knot")
master = t.server("knot")
slave = t.server("knot")
zones = t.zone_rnd(150, dnssec=False, records=5)

t.link(zones, master, slave)

master.disable_notify = True
slave.disable_notify = True

for zone in zones:
    master.dnssec(zone).enable = True
    master.dnssec(zone).nsec3 = True
    master.dnssec(zone).nsec3_iters = 1
    master.dnssec(zone).nsec3_salt_len = 1
    master.dnssec(zone).nsec3_opt_out = False

t.start()
master.zones_wait(zones)
slave.ctl("zone-refresh")
slave.zones_wait(zones)

# initial convenience check
t.xfr_diff(master, slave, zones)

# update master
#for zone in zones:
#  master.zone_backup(zone, flush=True)
master.flush()
t.sleep(9)
for zone in zones:
    master.random_ddns(zone)

t.sleep(1)
master.ctl("zone-refresh")

t.sleep(1) # zones_wait fails if an empty update is generated
after_update = master.zones_wait(zones)

#for zone in zones:
#  master.zone_backup(zone, flush=True)

# sync slave with current master's state
slave.ctl("zone-refresh")
slave.zones_wait(zones, after_update, equal=True, greater=False)

# flush so that we can do zone_verify
##slave.flush()

# re-sign master and check that the re-sign made nothing
master.ctl("zone-sign")
after_update15 = master.zones_wait(zones, after_update, equal=False, greater=True)

t.xfr_diff(master, slave, zones, no_rrsig_rdata=True)
##for zone in zones:
##    slave.zone_verify(zone)

#for zone in zones:
#  master.zone_backup(zone, flush=True)

t.end()
