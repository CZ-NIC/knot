#!/usr/bin/env python3

'''Test for IXFR of many zones from one Knot to another'''

from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")
zones = t.zone_rnd(400, records=10, dnssec=False)

t.link(zones, master, slave, ixfr=True)

t.start()

# Wait for AXFR to slave server.
serials_init = master.zones_wait(zones)
slave.zones_wait(zones)

# Update zone files on master.
for zone in zones:
    master.update_zonefile(zone, random=True)

master.reload()

# Wait for IXFR to slave.
master.zones_wait(zones, serials_init)
slave.zones_wait(zones, serials_init)

# Compare IXFR between servers.
t.xfr_diff(master, slave, zones, serials_init)

t.end()
