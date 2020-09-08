#!/usr/bin/env python3

'''Test for mitigation of cross-message compression on multi-message-AXFR'''

from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")
zones = t.zone("example.", storage=".")

t.link(zones, master, slave)

master.no_xfr_edns = True

t.start()

master.zones_wait(zones)
slave.zones_wait(zones)
t.xfr_diff(master, slave, zones)

t.end()
