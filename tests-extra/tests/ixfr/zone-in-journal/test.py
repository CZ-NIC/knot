#!/usr/bin/env python3

'''Test of zone-in-journal: slave should merge changesets into zone-in-journal'''

from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")

zone = t.zone_rnd(1, records=100, dnssec=False)

t.link(zone, master, slave)

slave.max_journal_usage = 150 * 1024

master.conf_zone(zone).zonefile_sync = "0"
master.conf_zone(zone).journal_content = "none"

slave.conf_zone(zone).zonefile_sync = "-1"
slave.conf_zone(zone).zonefile_load = "none"
slave.conf_zone(zone).journal_content = "all"

master.dnssec(zone).enable = "true"

t.start()

master.zone_wait(zone)
serial = slave.zone_wait(zone)

for i in range(1, 8):
    master.ctl("zone-sign")
    serial = slave.zone_wait(zone, serial=serial)

slave.stop()
slave.start() # now the slave starts the zone from zone-in-journal and does not XFR

slave.zone_wait(zone)

slave.ctl("zone-refresh") # this is just to ensure that he gives up

t.xfr_diff(master, slave, zone)

t.end()
