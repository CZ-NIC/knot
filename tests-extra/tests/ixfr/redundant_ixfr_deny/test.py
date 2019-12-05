#!/usr/bin/env python3

'''Test that removal of nonexisting or addition of existing record over IXFR
is not accepted by a slave'''

from dnstest.test import Test
from dnstest.utils import *

t = Test()

master = t.server("knot")
slave = t.server("knot")

zone = t.zone("existing.", storage=".")

t.link(zone, master, slave, ixfr=True)

slave.update_zonefile(zone, version="slave0")

t.start()

serial = master.zone_wait(zone)
slave.zone_wait(zone)

# Check that removal of nonexisting record is not accepted

master.update_zonefile(zone, version=1)
master.reload()

serial = slave.zone_wait(zone, serial)
if not slave.log_search("no such record in zone found") or not slave.log_search("fallback to AXFR"):
    detail_log("IXFR ignored a removal of a nonexisting RR and did not fall back to AXFR")
    set_err("IXFR ERROR")
t.xfr_diff(master, slave, zone)

# Check that addition of existing record is not accepted

slave.stop()
slave.update_zonefile(zone, version="slave1")
slave.start()
slave.zone_wait(zone)

master.update_zonefile(zone, version=2)
master.reload()

serial = slave.zone_wait(zone, serial)
if not slave.log_search("such record already exists in zone") or not slave.log_search("fallback to AXFR"):
    detail_log("IXFR ignored an addition of existent RR and did not fall back to AXFR")
    set_err("IXFR ERROR")
t.xfr_diff(master, slave, zone)

t.end()
