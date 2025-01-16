#!/usr/bin/env python3

'''Test for DNAME check at the zone apex'''

import random
from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")
ZONE = "test."
zones = t.zone(ZONE, storage=".")

t.link(zones, master, slave)

master.zonefile_sync = 0
master.zonefile_load = "difference-no-serial"
master.zones[ZONE].journal_content = "all"

if random.choice([False, True]):
    master.dnssec(zones[0]).enable = True
    if random.choice([False, True]):
        master.dnssec(zones[0]).nsec3 = True

t.start()

# Check if the zone was accepted via AXFR
serial = master.zones_wait(zones)
slave.zones_wait(zones)
t.xfr_diff(master, slave, zones)
resp = slave.dig(ZONE, "DNAME")
resp.check(rcode="NOERROR", rdata="example.com.")

# Check if possibly signed zone (upon flush) can be parsed
master.stop()
t.sleep(1)
master.zones[ZONE].zfile.append_rndTXT(ZONE)
master.start()

# Check if the zone was accepted via IXFR
master.zones_wait(zones, serial)
slave.zones_wait(zones, serial)
t.xfr_diff(master, slave, zones)
resp = slave.dig(ZONE, "DNAME")
resp.check(rcode="NOERROR", rdata="example.com.")

t.end()
