#!/usr/bin/env python3

'''Test for AXFR fallback after failed IXFR.'''

from dnstest.test import Test
from dnstest.utils import *

t = Test(stress=False)

master = t.server("knot")
slave = t.server("knot")
zone = t.zone_rnd(1, records=1000)
t.link(zone, master, slave, ixfr=True)

for z in zone:
    master.dnssec(z).enable = True
master.disable_notify = True
slave.zones[zone[0].name].retry_max = 10

t.start()

serial = slave.zones_wait(zone)

# Re-sign master and kill it once IXFR is running
master.ctl("zone-sign")
master.zones_wait(zone, serial)
slave.ctl("zone-refresh")
t.sleep(0.1 if slave.valgrind else 0.01)
master.kill()

t.sleep(5)
master.start()

# check that IXFR was performed and no fallback to AXFR
slave.zones_wait(zone, serial)
t.xfr_diff(master, slave, zone, serial)

if slave.log_search("fallback to AXFR"):
    set_err("AXFR FALLBACK")

t.end()
