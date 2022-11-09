#!/usr/bin/env python3

'''Test of zone transfers over QUIC.'''

from dnstest.test import Test
from dnstest.utils import Failed,Skip
import random

t = Test()

master = t.server("knot")
slave = t.server("knot")
zone = t.zone_rnd(1, records=15) + t.zone_rnd(1, records=60) + t.zone_rnd(1, records=100) + t.zone_rnd(1, records=600)

t.link(zone, master, slave)
master.tls_set("tls.crt", "tls.key", t.data_dir)

for z in zone:
    master.dnssec(z).enable = True

try:
    t.start()
except Failed as e:
    stderr = t.out_dir + "/" + str(e).split("'")[1] + "/stderr"
    with open(stderr) as fstderr:
        if "QUIC" in fstderr.readline():
            raise Skip("QUIC support not compiled in")
    raise e

serial = master.zones_wait(zone)
slave.zones_wait(zone, serial, equal=True, greater=False)
t.xfr_diff(master, slave, zone)

for z in zone:
     master.random_ddns(z, allow_empty=False)

slave.zones_wait(zone, serial)
t.xfr_diff(master, slave, zone, serial)

t.end()
