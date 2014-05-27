#!/usr/bin/env python3

'''Test for IXFR from Bind to Knot'''

from dnstest.test import Test

t = Test()

master = t.server("bind")
slave = t.server("knot")
zones = t.zone_rnd(5, records=50) + t.zone("wild.") + \
        t.zone("cname-loop.") + t.zone("records.")

t.link(zones, master, slave, ixfr=True)

t.start()

# Wait for AXFR to slave server.
serials_init = master.zones_wait(zones)
slave.zones_wait(zones)

serials_prev = serials_init
for i in range(4):
    # Update zone files on master.
    for zone in zones:
        master.update_zonefile(zone, random=True)
    master.reload()

    # Wait for IXFR to slave.
    serials = master.zones_wait(zones, serials_prev)
    slave.zones_wait(zones, serials_prev)
    serials_prev = serials

    # Compare IXFR between servers.
    t.xfr_diff(master, slave, zones, serials_init)

t.end()
