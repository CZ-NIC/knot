#!/usr/bin/env python3

'''Test for IXFR from Knot to Knot'''

import os
from dnstest.libknot import libknot
from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")
zone = t.zone(".")

t.link(zone, master, slave, ixfr=True)
ctl = libknot.control.KnotCtl()

t.start()

slave.zones_wait(zone)

ctl.connect(os.path.join(slave.dir, "knot.sock"))

master.update_zonefile(zone, random=True)

ctl.send_block(cmd="zone-begin")
resp = ctl.receive_block()

master.reload()
t.sleep(2)

for j in range(2):
    ctl.send_block(cmd="zone-abort")
    resp = ctl.receive_block()
    ctl.send_block(cmd="zone-begin")
    resp = ctl.receive_block()

t.end()
