#!/usr/bin/env python3

'''Test of incrementaly adding zone signatures and NSEC3 into big zone.'''

from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")

RECORDS = 12000
if master.valgrind:
    RECORDS = 2000

zones = t.zone_rnd(1, records=RECORDS, dnssec=False)

t.link(zones, master, slave, ixfr=True)

master.journal_db_size = 200 * 1024 * 1024
slave.journal_db_size = 200 * 1024 * 1024
master.journal_max_usage = 100 * 1024 * 1024
slave.journal_max_usage = 100 * 1024 * 1024

t.start()
serial = slave.zones_wait(zones)

for z in zones:
    master.dnssec(z).enable = True
    master.dnssec(z).nsec3 = True
master.gen_confile()
master.reload()

slave.zones_wait(zones, serial)

t.end()
