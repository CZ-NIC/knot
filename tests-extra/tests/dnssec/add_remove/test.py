#!/usr/bin/env python3

'''Test for DNSSEC additions and removals'''

from dnstest.utils import *
from dnstest.test import Test

CHANGE_COUNT = 9

def update_zone(master, slave, zone, changes, change_serial=False, serials=None):
    for i in changes:
        serial = master.zone_wait(zone)
        master.update_zonefile(zone, version=i)
        if change_serial:
            # update zone serial to one given in the 'serials' list
            master.zones[zone[0].name].zfile.update_soa(serial=serials[i])
            serial = serials[i]
        else:
            serials.append(serial)
        master.reload()
        t.sleep(1)
        master.flush()
        t.sleep(1)
        master.zone_verify(zone)
        slave.zone_wait(zone, serial)
        t.xfr_diff(master, slave, zone)

def do_steps(master, slave, zone):
    # add records
    serials = []
    update_zone(master, slave, zone, range(1, CHANGE_COUNT + 1),
                change_serial=False, serials=serials)
    # remove added records, in descending order
    rev = list(range(1, CHANGE_COUNT + 1))
    rev.reverse()
    # increase serials so that server accepts them
    serials = list(map(lambda x: x + 1000, serials))
    serials.reverse()
    update_zone(master, slave, zone, rev[1:], change_serial=True, serials=serials)

t = Test()

# Create NSEC and NSEC3 servers
nsec_master = t.server("knot")
nsec3_master = t.server("knot")
nsec_slave = t.server("bind")
nsec3_slave = t.server("bind")

zone = t.zone("example.", storage=".")

t.link(zone, nsec_master, nsec_slave)
t.link(zone, nsec3_master, nsec3_slave)

# Enable autosigning
nsec_master.dnssec(zone).enable = True

nsec3_master.dnssec(zone).enable = True
nsec3_master.dnssec(zone).nsec3 = True

t.start()

check_log("============ testing NSEC changes ===============")
do_steps(nsec_master, nsec_slave, zone)
check_log("============ testing NSEC3 changes ==============")
do_steps(nsec3_master, nsec3_slave, zone)

t.end()
