#!/usr/bin/env python3

'''Test of handling large catalog with changes.'''

from dnstest.test import Test
from dnstest.utils import set_err, detail_log
import os
import random
import time

UPDATES = 5
ADD_ZONES = 11
REM_ZONES = 7
DNSSEC = True

t = Test(stress=False)

master = t.server("knot")
slave = t.server("knot")

catz = t.zone("example.")

t.link(catz, master, slave)

cz = master.zones[catz[0].name]

master.cat_generate(cz)
slave.cat_interpret(cz)

slave.dnssec(catz[0]).enable = DNSSEC
slave.dnssec(catz[0]).alg = "ECDSAP256SHA256"
slave.zones[catz[0].name].journal_content = "all"
slave.journal_db_size = 200 * 1024 * 1024

if master.valgrind:
    master.tcp_idle_timeout = 15000

t.start()

slave.zone_wait(catz, udp=False, tsig=True)

for i in range(UPDATES):
    zone_add = t.zone_rnd(ADD_ZONES, records=5, dnssec=False)
    t.link(zone_add, master, slave)
    for z in zone_add:
        master.cat_member(z, catz)
        slave.cat_hidden(z)
    master.gen_confile()
    master.reload()
    slave.zones_wait(zone_add)

    zone_rem = []
    REM_PERCENT = REM_ZONES * 100 / len(master.zones) + 1
    for z in master.zones:
        if z != catz[0].name and random.random() * 100  < REM_PERCENT:
            zone_rem.append(z)
    serial_bef_rem = slave.zone_wait(catz, udp=False, tsig=True)
    for z in zone_rem:
        master.zones.pop(z)
    master.gen_confile()
    master.reload()
    slave.zone_wait(catz, serial_bef_rem, udp=False, tsig=True)
    t.sleep(5)
    for z in zone_rem:
        resp = slave.dig(z, "SOA")
        if resp.count("SOA") > 0:
            # allowed: REFUSED (zone not exists)
            #          NXDOMAIN (in bailiwick of another existing zone)
            #          NODATA (ditto)
            # not allowed: NOERROR+data (zone exists with this name)
            resp.check(rcode="REFUSED")

t.end()
