#!/usr/bin/env python3

'''Test for dropping of out of zone records during incoming XFR'''

from dnstest.test import Test

t = Test()

master = t.server("bind")
slave = t.server("knot")
zone = t.zone("out-of-zone.")

t.link(zone, master, slave)

t.start()

master.zones_wait(zone)
slave.zones_wait(zone)

t.xfr_diff(master, slave, zone)

t.end()
