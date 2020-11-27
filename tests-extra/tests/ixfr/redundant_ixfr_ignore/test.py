#!/usr/bin/env python3

'''Test that removal of nonexisting or addition of existing record over IXFR
is ignored/denied by a slave'''

import random

from dnstest.test import Test
from dnstest.utils import *

IGNORE = random.choice([True, False])

t = Test()

master = t.server("knot")
slave = t.server("knot")

zone = t.zone("existing.", storage=".")

t.link(zone, master, slave, ixfr=True)

if IGNORE:
    slave.ixfr_benevolent = True

slave.update_zonefile(zone, version="slave0")

t.start()

serial = master.zone_wait(zone)
slave.zone_wait(zone)

# Check that removal of nonexisting record is ignored/denied

master.update_zonefile(zone, version=1)
master.reload()

serial = slave.zone_wait(zone, serial)
if IGNORE:
    if slave.log_search("fallback to AXFR"):
        set_err("AXFR FALLBACK")
else:
    if not slave.log_search("no such record in zone found") or not slave.log_search("fallback to AXFR"):
        detail_log("IXFR ignored a removal of a nonexisting RR and did not fall back to AXFR")
        set_err("IXFR ERROR")

t.xfr_diff(master, slave, zone)

# Check that addition of existing record is ignored/denied

slave.stop()
slave.update_zonefile(zone, version="slave1")
slave.start()
slave.zone_wait(zone)

master.update_zonefile(zone, version=2)
master.reload()

serial = slave.zone_wait(zone, serial)
if IGNORE:
    if slave.log_search("fallback to AXFR"):
        set_err("AXFR FALLBACK")
else:
    if not slave.log_search("such record already exists in zone") or not slave.log_search("fallback to AXFR"):
        detail_log("IXFR ignored an addition of existent RR and did not fall back to AXFR")
        set_err("IXFR ERROR")

t.xfr_diff(master, slave, zone)

t.end()
