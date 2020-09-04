#!/usr/bin/env python3

'''Test for AXFR from Knot to Knot'''

from dnstest.test import Test

t = Test(stress=False)

master = t.server("knot")
slave = t.server("knot")
zones = t.zone_rnd(4, records=100, dnssec=True)

t.link(zones, master, slave)

t.start()

master.zones_wait(zones)
slave.zones_wait(zones)
t.xfr_diff(master, slave, zones)

t.end()
