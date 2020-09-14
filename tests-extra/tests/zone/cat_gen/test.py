#!/usr/bin/env python3

'''Test of Catalog zone generation.'''

from dnstest.test import Test
from dnstest.utils import set_err, detail_log

t = Test()

master = t.server("knot")
slave = t.server("knot")

catz = t.zone("example.")
zone = t.zone("example.com.")

t.link(catz, master, slave)
t.link(zone, master)

for name in master.zones:
   master.zones[name].catalog_gen_link(master.zones[catz[0].name])

slave.zones[catz[0].name].catalog = True

t.start()

slave.zones_wait(zone)

t.end()
