#!/usr/bin/env python3

'''Test race conditions about incomming NOTIFY during zonedb-reload'''

from dnstest.test import Test
from dnstest.utils import *

import random
import threading

t = Test()

master = t.server("knot")
slave = t.server("knot")
zones = t.zone_rnd(60, dnssec=False, records=10)
t.link(zones, master, slave, ixfr=True)

t.start()

serials = slave.zones_wait(zones)

def send_reload(server):
    server.ctl("reload")

def send_update(up):
    up.send()

for z in zones:
    up = master.update(z)
    up.add("dojdojwodijowjeojdwe", 3600, "A", "1.2.3.4")

    threading.Thread(target=send_update, args=[up]).start()

t.sleep(random.choice([0.1, 0.2, 0.5, 1, 2, 4]))

slave.reload()

slave.zones_wait(zones, serials)

t.end()
