#!/usr/bin/env python3

'''Test for Knot clean-up after interruption of AXFR from Bind'''

from dnstest.test import Test
from dnstest.utils import *

t = Test()

master = t.server("bind")
slave = t.server("knot")
zones = t.zone_rnd(1, dnssec=False, records=50000)

t.link(zones, master, slave)

t.start()

t.sleep(2)
check_log("Killing master %s" % master.name)
master.proc.kill()
t.sleep(5)

t.end()
