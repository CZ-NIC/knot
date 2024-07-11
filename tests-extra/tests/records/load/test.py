#!/usr/bin/env python3

'''Test for loading of dumped zone'''

from dnstest.test import Test

t = Test()

pre_master = t.server("knot") # For records unknown to Bind.
master = t.server("bind")
slave = t.server("knot")
reference = t.server("knot")

zones_both = t.zone_rnd(2) + t.zone(".") + t.zone("records.") + t.zone("svcb", storage=".") + \
             t.zone("future", storage=".")
zones_knot = t.zone("knot-only", storage=".")
zones = zones_both + zones_knot

t.link(zones_knot, pre_master, master)
t.link(zones, master, slave)
t.link(zones, reference)

t.start()

# Wait for servers.
master.zones_wait(zones)
slave.zones_wait(zones + zones_knot)
reference.zones_wait(zones + zones_knot)

# Dump zones on slave.
slave.flush(wait=True)

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
