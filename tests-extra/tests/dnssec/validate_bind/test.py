#!/usr/bin/env python3

'''Test for DNSSEC validation of Bind9 master by Knot slave'''

from dnstest.test import Test

t = Test()

master = t.server("bind")
slave = t.server("knot")
zones_nsec = t.zone_rnd(3, records=40, dnssec=False)
zones_nsec3 = t.zone_rnd(3, records=40, dnssec=False)
zones = zones_nsec + zones_nsec3

t.link(zones, master, slave, ixfr=True, ddns=True)

for z in zones:
    master.dnssec(z).enable = True
    slave.dnssec(z).validate = True

for z in zones_nsec3:
    master.dnssec(z).nsec3 = True
    master.dnssec(z).nsec3_opt_out = True
    slave.dnssec(z).nsec3 = True

t.start()

serials_init = master.zones_wait(zones)
slave.zones_wait(zones)

serials_prev = serials_init
for i in range(4):
    for z in zones:
        master.random_ddns(z, allow_empty=False)

    serials = master.zones_wait(zones, serials_prev)
    slave.zones_wait(zones, serials_prev)
    serials_prev = serials

    master.flush()

    t.xfr_diff(master, slave, zones, serials_init)

t.end()
