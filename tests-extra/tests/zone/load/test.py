#!/usr/bin/env python3

'''Test for loading of dumped zone'''

from dnstest.test import Test

t = Test()

master = t.server("bind")
slave = t.server("knot")
reference = t.server("bind")

zones = t.zone_rnd(10) + t.zone(".") + t.zone("wild.") + t.zone("cname-loop.")

t.link(zones, master, slave)
t.link(zones, reference)

t.start()

# Wait for AXFR and dump zones.
master.zones_wait(zones)
slave.zones_wait(zones)
slave.flush()

# Stop master.
master.stop()

# Reload dumped zone files.
slave.stop()
slave.start()

# Compare slave with reference server
slave.zones_wait(zones)
t.xfr_diff(reference, slave, zones)

t.end()
