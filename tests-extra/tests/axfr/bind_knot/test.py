#!/usr/bin/env python3

'''Test for AXFR from Bind to Knot'''

from dnstest.test import Test

t = Test()

master = t.server("bind")
slave = t.server("knot")
zones = t.zone_rnd(10)
zones.update(t.zone("."))
zones.update(t.zone("wild."))
zones.update(t.zone("cname-loop."))

t.link(zones, master, slave)

t.start()

master.zones_wait(zones)
slave.zones_wait(zones)
t.xfr_diff(master, slave, zones)

t.end()
