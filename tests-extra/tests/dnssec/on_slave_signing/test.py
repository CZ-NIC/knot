#!/usr/bin/env python3

'''Test for automatic DNSSEC signing on a slave Knot'''

from dnstest.utils import *
from dnstest.test import Test

serial = 20

def test_update(master, slave, zone):
    slave.zone_wait(zone, serial, equal=True)

    master.update_zonefile(zone, version=1)
    master.reload()

    slave.zone_wait(zone, serial+1, equal=True)


t = Test(address=4, stress=False, tsig=False)

# Create master and slave servers
bind_master = t.server("knot")
knot_slave1 = t.server("knot")

zone = t.zone("example.com.", storage=".")

t.link(zone, bind_master, knot_slave1, ixfr=True)

# Enable autosigning on slave
knot_slave1.dnssec(zone).enable = True
knot_slave1.dnssec(zone).nsec3 = True   #!!!!!

t.start()

test_update(bind_master, knot_slave1, zone)

t.end()
