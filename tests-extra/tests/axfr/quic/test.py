#!/usr/bin/env python3

'''Test of zone transfers over QUIC.'''

from dnstest.test import Test
from dnstest.utils import Failed,Skip
import random

t = Test(quic=True, tsig=False) ####

master = t.server("knot")
slave = t.server("knot")
rnd_zones = t.zone_rnd(1, records=15) + t.zone_rnd(1, records=60) + \
            t.zone_rnd(1, records=100) + t.zone_rnd(1, records=600)
zones = t.zone(".") + rnd_zones

t.link(zones, master, slave)

for z in rnd_zones:
    master.dnssec(z).enable = True

def upd_check_zones(master, slave, zones, prev_serials):
    for z in zones:
         master.random_ddns(z, allow_empty=False)

    serials = slave.zones_wait(zones, prev_serials)
    t.xfr_diff(master, slave, zones, prev_serials)
    return serials

try:
    t.start()
except Failed as e:
    stderr = t.out_dir + "/" + str(e).split("'")[1] + "/stderr"
    with open(stderr) as fstderr:
        if "QUIC" in fstderr.readline():
            raise Skip("QUIC support not compiled in")
    raise e

serials = master.zones_wait(zones)
slave.zones_wait(zones, serials, equal=True, greater=False)
t.xfr_diff(master, slave, zones)

# Authenticate master
master.get_cert_key()
slave.gen_confile()
slave.reload()

serials = upd_check_zones(master, slave, rnd_zones, serials)

# Authenticate slave
slave.get_cert_key()
master.gen_confile()
master.reload()

serials = upd_check_zones(master, slave, rnd_zones, serials)

t.end()
