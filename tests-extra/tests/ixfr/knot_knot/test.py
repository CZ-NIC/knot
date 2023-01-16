#!/usr/bin/env python3

'''Test for IXFR from Knot to Knot (also over a UNIX socket)'''

import os
import random
from dnstest.test import Test

t = Test()

use_unix = random.choice([True, False])
master_address = os.path.join(t.out_dir, "master.sock") if use_unix else None
slave_address = os.path.join(t.out_dir, "slave.sock") if use_unix else None

master = t.server("knot", address=master_address)
slave = t.server("knot", address=slave_address)
zones = t.zone_rnd(5, records=50) + t.zone("records.")

t.link(zones, master, slave, ixfr=True)

if master.valgrind:
    master.semantic_check = False
    slave.semantic_check = False

master.tcp_io_timeout = 3000
slave.tcp_io_timeout = 3000
slave.tcp_remote_io_timeout = 8000

t.start()

# Wait for AXFR to slave server.
serials_init = master.zones_wait(zones, use_ctl=use_unix)
slave.zones_wait(zones, use_ctl=use_unix)

serials_prev = serials_init
for i in range(4):
    # Update zone files on master.
    for zone in zones:
        master.update_zonefile(zone, random=True)
    master.reload()

    # Wait for IXFR to slave.
    serials = master.zones_wait(zones, serials_prev, use_ctl=use_unix)
    slave.zones_wait(zones, serials_prev, use_ctl=use_unix)
    serials_prev = serials

    # Compare IXFR between servers.
    if not use_unix:
        t.xfr_diff(master, slave, zones, serials_init)

t.end()
