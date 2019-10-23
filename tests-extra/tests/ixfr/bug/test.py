#!/usr/bin/env python3

'''Test for IXFR from Knot to Knot'''

import os
from dnstest.libknot import libknot
from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")
zones = t.zone(".")

t.link(zones, master, slave, ixfr=True)
ctl = libknot.control.KnotCtl()

t.start()

# Wait for AXFR to slave server.
serials_init = master.zones_wait(zones)
slave.zones_wait(zones)

ctl.connect(os.path.join(slave.dir, "knot.sock"))

serials_prev = serials_init
for i in range(4):
#    input("%s" % i)
    # Update zone files on master.
    for zone in zones:
        master.update_zonefile(zone, random=True)

    ctl.send_block(cmd="zone-begin")

    master.reload()

    for j in range(2):
        ctl.send_block(cmd="zone-abort")
        resp = ctl.receive_block()
        ctl.send_block(cmd="zone-begin")
        resp = ctl.receive_block()

    # Wait for IXFR to slave.
    serials = master.zones_wait(zones, serials_prev)
    slave.zones_wait(zones, serials_prev)
    serials_prev = serials

t.end()
