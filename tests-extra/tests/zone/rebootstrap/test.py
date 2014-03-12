#!/usr/bin/env python3

'''Test for auto-rebootstrap if the slave zone file is invalid.'''

from dnstest.test import Test

t = Test()

master = t.server("bind")
slave = t.server("knot")

zone = t.zone("invalid.", storage=".")

t.link(zone, master, slave)

# Create invalid zone file.
slave.update_zonefile(zone, version=1)

t.start()

# Wait for zones and compare them.
master.zones_wait(zone)
slave.zones_wait(zone)
t.xfr_diff(master, slave, zone)

t.end()
