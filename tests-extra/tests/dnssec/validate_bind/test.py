#!/usr/bin/env python3

'''Test for DNSSEC validation of Bind9 master by Knot slave'''

from dnstest.test import Test

t = Test()

master = t.server("bind")
slave = t.server("knot")
zones = t.zone_rnd(1, records=10)

t.link(zones, master, slave, ixfr=True, ddns=True)

for z in zones:
    master.dnssec(z).enable = True

    slave.dnssec(z).validate = True
    slave.dnssec(z).nsec3 = True

t.start()

serials_init = master.zones_wait(zones)
slave.zones_wait(zones)

serials_prev = serials_init
for i in range(2):
    for z in zones:
        master.random_ddns(z, allow_empty=False)

    serials = master.zones_wait(zones, serials_prev)
    slave.zones_wait(zones, serials_prev)
    serials_prev = serials

    t.xfr_diff(master, slave, zones, serials_init)

t.end()
