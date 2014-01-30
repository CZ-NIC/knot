#!/usr/bin/env python3

'''Test for support of obsolete records over XFR'''

from dnstest.test import Test

t = Test()

master = t.server("bind")
slave = t.server("knot")
zone = t.zone("obsolete.", storage=".")

t.link(zone, master, slave)

t.start()

master.zones_wait(zone)
slave.zones_wait(zone)

t.xfr_diff(master, slave, zone)

t.end()
