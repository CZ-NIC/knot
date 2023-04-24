#!/usr/bin/env python3

'''Test for AXFR from Knot to Knot'''

from dnstest.test import Test

t = Test(stress=False)

master = t.server("knot")
slave = t.server("knot")
zones = t.zone("records.")

t.link(zones, master, slave)

t.start()

t.sleep(3)

t.end()
