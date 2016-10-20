#!/usr/bin/env python3

'''Test for loading of dumped zone'''

from dnstest.test import Test

t = Test()

master = t.server("bind")
slave = t.server("knot")
reference = t.server("bind")

zones = t.zone_rnd(4) + t.zone(".") + t.zone("records.")

t.link(zones, master, slave)
t.link(zones, reference)

t.start()

# Wait for servers.
master.zones_wait(zones)
slave.zones_wait(zones)
reference.zones_wait(zones)

# Dump zones on slave.
slave.flush()

# Compare master with reference server
t.xfr_diff(reference, master, zones)

# Compare slave with reference server
t.xfr_diff(reference, slave, zones)

# Stop master.
master.stop()

# Reload dumped zone files.
slave.stop()
slave.start()

# Compare reloaded slave with reference server
slave.zones_wait(zones)
t.xfr_diff(reference, slave, zones)

t.end()
