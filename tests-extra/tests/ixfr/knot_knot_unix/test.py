#!/usr/bin/env python3

'''Test for IXFR from Knot to Knot over a UNIX socket'''

import os
from dnstest.test import Test

t = Test()

master = t.server("knot", address=os.path.join(t.out_dir, "master.sock"))
slave = t.server("knot", address=os.path.join(t.out_dir, "slave.sock"))
zones = t.zone_rnd(5, records=50)

t.link(zones, master, slave, ixfr=True)

t.start()

# Wait for AXFR to slave server.
serials_init = master.zones_wait(zones, use_ctl=True)
slave.zones_wait(zones, use_ctl=True)

serials_prev = serials_init
for i in range(4):
    # Update zone files on master.
    for zone in zones:
        master.update_zonefile(zone, random=True)
    master.reload()

    # Wait for IXFR to slave.
    serials = master.zones_wait(zones, serials_prev, use_ctl=True)
    slave.zones_wait(zones, serials_prev, use_ctl=True)
    serials_prev = serials

t.end()
