#!/usr/bin/env python3

'''Flushing the zone after ZONEMD generation.'''

from dnstest.test import Test
from dnstest.utils import *

def has_zonemd(server, zone, alg):
    zfn = server.zones[zone.name].zfile.path
    with open(zfn) as zf:
        for line in zf:
            rr = line.split()
            if rr[0].lower() == zone.name.lower() and rr[2] == "ZONEMD" and rr[5] == alg:
                return True
    return False

def check_zonemd(server, zone, alg):
    for z in zone:
        if not has_zonemd(server, z, alg):
            set_err("NO ZONEMD in %s" % z.name)

t = Test()

master = t.server("knot")

zone = t.zone_rnd(2, dnssec=False, records=10)
t.link(zone, master)

master.zonefile_sync = 0
master.zonemd_generate = "zonemd-sha384"

t.start()

master.zones_wait(zone)
t.sleep(4)
check_zonemd(master, zone, "1")

t.end()
