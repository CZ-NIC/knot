#!/usr/bin/env python3

'''Test for NSEC3 adjust bug, when the DELETED check goes to wrong half of the bi-node'''

from dnstest.utils import *
from dnstest.test import Test
import random

t = Test()

master = t.server("knot")
slave = t.server("knot")
zones = t.zone("example.com.", storage=".")

t.link(zones, master, slave)

for zone in zones:
    master.dnssec(zone).enable = True
    master.dnssec(zone).nsec3 = True
    master.dnssec(zone).nsec3_iters = 2
    master.dnssec(zone).nsec3_salt_len = 10
    master.dnssec(zone).nsec3_opt_out = True

t.start()
master.zones_wait(zones)

# zone update that doesn't affect deleg.example.com.
up = master.update(zones)
up.add("egal.example.com.", 3600, "AAAA", "100::200")
up.send()
t.sleep(1)

# zone update that affects deleg.example.com.
up = master.update(zones)
up.add("deleg.example.com.", 3600, "AAAA", "1::5")
up.send()
t.sleep(1)

# zone update that makes it a delegation
up = master.update(zones)
up.delete("deleg.example.com.", "ANY")
up.add("deleg.example.com.", 3600, "NS", "dns2.example.com.")
up.send()
t.sleep(1)

# zone update that affects deleg.example.com.
up = master.update(zones)
up.delete("deleg.example.com.", "ANY")
up.add("deleg.example.com.", 3600, "A", "1.2.3.6")
up.send()
t.sleep(1)

slave.zone_wait(zones)

t.end()
