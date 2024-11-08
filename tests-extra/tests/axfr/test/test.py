#!/usr/bin/env python3

'''Test for AXFR from Knot to Knot'''

from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")
zones = t.zone("example.com.", storage=".")

t.link(zones, master, slave)

t.start()

master.stop()
slave.zones_wait(zones)
slave.ctl("zone-begin example.com")
t.sleep(11)

t.end()
