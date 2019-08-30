#!/usr/bin/env python3

'''Test for IXFR from Knot to Bind with TTL changed by RR addition'''

from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("bind")
zones = t.zone("example.com.")

t.link(zones, master, slave, ixfr=True)

t.start()
serials_init = slave.zones_wait(zones)

up = master.update(zones)
up.add("example.com.", 500, "MX", "20 dns1")
up.send("NOERROR")

slave.zones_wait(zones, serials_init)

t.xfr_diff(master, slave, zones, serials_init)

t.end()
