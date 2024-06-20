#!/usr/bin/env python3

'''Test storing changeset with serial 1718378855 (0x666c6167, in ASCII "flag") into journal.'''

from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")

ZONE = "example."
zones = t.zone(ZONE)

t.link(zones, master, slave)

master.zones[ZONE].zfile.update_soa(serial=1718378850)

master.journal_max_depth = 10

t.start()
serials = master.zones_wait(zones)

for i in range(20):
    up = master.update(zones[0])
    up.add("xxx" + str(i), 3600, "A", "1.2.3." + str(i))
    up.send()
    serials = master.zones_wait(zones, serials)

t.end()
