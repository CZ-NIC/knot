#!/usr/bin/env python3

"""
Zone persistence on a slave server without AXFR.
"""

from dnstest.test import Test

t = Test()

zone = t.zone_rnd(1, records=1, dnssec=False)[0]
zone.update_soa(serial=1, refresh=600, retry=600, expire=3600)

master = t.server("knot")
slave = t.server("knot")

slave.zonefile_sync = 24 * 60 * 60
t.link([zone], master, slave)

t.start()

# verify zone boostrap
for server in [master, slave]:
    server.zone_wait(zone)

# update zone
master.zones[zone.name].zfile.update_soa(serial=10)
master.reload()
for server in [master, slave]:
    server.zone_wait(zone, serial=9)

# stop servers
master.stop()
slave.stop()

# verify zone persistence after boostrap
slave.start()
slave.zone_wait(zone, serial=9)

# update zone
master.zones[zone.name].zfile.update_soa(serial=20)
master.start()
for server in [master, slave]:
    server.zone_wait(zone, serial=19)

# stop servers
master.stop()
slave.stop()

# verify zone persistence without journal
slave.start()
slave.zone_wait(zone, serial=19)

t.stop()
