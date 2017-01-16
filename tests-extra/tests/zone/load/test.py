#!/usr/bin/env python3

'''Test for slave zone refresh when loading.'''

from dnstest.test import Test
from dnstest.utils import *

t = Test()

master = t.server("knot")
slave = t.server("knot")
slave.disable_notify = True

zone_del = t.zone_rnd(1, dnssec=False)
zone_upd = t.zone_rnd(1, dnssec=False)
zones = zone_del + zone_upd
t.link(zones, master, slave)

# Decrease the zone refresh timer.
master.zones[zone_del[0].name].zfile.update_soa(refresh=4)

t.start()

serial_del_init = master.zone_wait(zone_del)
serial_upd_init = master.zone_wait(zone_upd)
slave.zones_wait(zones)

slave.stop()

# Update a zonefile on the master.
master.update_zonefile(zone_upd, random=True)
master.reload()

# Remove a zonefile on the slave.
slave.clean(zone=zone_del, timers=False)

slave.start()

# Check for planned zone transfer if zone file deleted.
slave.zone_wait(zone_del, serial=serial_del_init, equal=True, greater=False)

# Check for untouched zone if retransfer already scheduled.
serial_upd = slave.zone_wait(zone_upd)
master.zone_wait(zone_upd, serial_upd, equal=False, greater=True)

t.end()
