#!/usr/bin/env python3

'''Test for record removal over IXFR to slave zone which doesn't contain this record'''

from dnstest.test import Test
from dnstest.utils import *

t = Test()

master = t.server("bind")
slave = t.server("knot")

zone = t.zone("existing.", storage=".")

t.link(zone, master, slave, ixfr=True)

# Remove the record from slave zone file (no SOA serial change).
slave.update_zonefile(zone, version=2)

t.start()

# Wait for zones.
serial = master.zone_wait(zone)
slave.zone_wait(zone)

# Update master file without the record (new SOA serial).
master.update_zonefile(zone, version=1)
master.reload()

if not slave.log_search("no such record in zone found") or not slave.log_search("fallback to AXFR"):
    detail_log("IXFR ignored a removal of a nonexistent RR and did not fall back to AXFR")
    set_err("IXFR ERROR")

# Wait for zones and compare them.
master.zone_wait(zone, serial)
slave.zone_wait(zone, serial)
t.xfr_diff(master, slave, zone)

t.end()
