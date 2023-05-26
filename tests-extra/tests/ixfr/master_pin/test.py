#!/usr/bin/env python3

'''Test of master pinning with tolerance period.'''

import os
import random
from dnstest.test import Test
from dnstest.utils import *

DISABLE_NOTIFY = random.choice([False, True])
PERIOD = 10

t = Test(address=4)

masterA = t.server("knot", address="127.0.0.2", via=True)
masterB = t.server("knot", address="127.0.0.3", via=True)
slave = t.server("knot", address="127.0.0.4", via=True)
zones = t.zone("example.", storage=("." if DISABLE_NOTIFY else None)) # The explicit zone has low refresh timer.
zone = zones[0]

t.link(zones, masterA, slave, ixfr=True)

slave.master_pin_tol = PERIOD

masterA.disable_notify = DISABLE_NOTIFY
masterB.disable_notify = DISABLE_NOTIFY
slave.disable_notify = DISABLE_NOTIFY

check_log("DISABLE_NOTIFY: " + str(DISABLE_NOTIFY))

t.start()

serials0 = slave.zones_wait(zones)

t.link(zones, masterB, slave, ixfr=True)
for srv in [ slave, masterB ]:
    srv.gen_confile()
    srv.reload()
t.sleep(10)

up = masterB.update(zone)
up.add("add1.example.", 3, "A", "1.2.3.100")
up.send()
t.sleep(PERIOD/2)
up = masterA.update(zone)
up.add("add1.example.", 3, "A", "1.2.3.101")
up.send()

serials1 = slave.zones_wait(zones, serials0)
q = slave.dig("add1.example.", "A")
q.check(rcode="NOERROR", rdata="1.2.3.101", nordata="1.2.3.100")
t.xfr_diff(masterA, slave, zones, serials0)

up = masterB.update(zone)
up.add("add2.example.", 3, "A", "1.2.3.100")
up.send()
t.sleep(PERIOD+(8 if DISABLE_NOTIFY else 2))
up = masterA.update(zone)
up.add("add2.example.", 3, "A", "1.2.3.101")
up.send()

serials2 = slave.zones_wait(zones, serials1)
q = slave.dig("add2.example.", "A")
q.check(rcode="NOERROR", rdata="1.2.3.100", nordata="1.2.3.101")

t.check_axfr_style_ixfr(slave, "example.", serials1["example."])

t.end()
