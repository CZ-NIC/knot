#!/usr/bin/env python3

'''Test for NSEC and NSEC3 fix after zone update (ddns, ixfr)'''

from dnstest.utils import *
from dnstest.test import Test
from dnstest.keys import Keymgr
import random

t = Test()

master = t.server("knot")
slave = t.server("knot")
zones = t.zone("log.", storage=".")
#zones = t.zone_rnd(100, dnssec=False, records=1)

t.link(zones, master, slave)

master.disable_notify = True
slave.disable_notify = True

for zone in zones:
    master.dnssec(zone).enable = True
    master.dnssec(zone).nsec3 = True
    master.dnssec(zone).nsec3_iters = 1
    master.dnssec(zone).nsec3_salt_len = 0
    master.dnssec(zone).nsec3_opt_out = False

master.gen_confile()

for zone in zones:
    Keymgr.run_check(master.confile, zone.name, "nsec3-salt", "-")

t.start()
master.zones_wait(zones)
slave.ctl("zone-refresh")
slave.zones_wait(zones)

master.flush()
input("x")
for zone in zones:
    up = master.update(zone)
    up.add("xyz.armstrong",  3600, "A", "1.1.1.1")
    up.add("xyz", 3600, "NS", "ns.log")
    up.send("NOERROR")

t.sleep(1) # zones_wait fails if an empty update is generated
after_update = master.zones_wait(zones)

# sync slave with current master's state
slave.ctl("zone-refresh")
slave.zones_wait(zones, after_update, equal=True, greater=False)

# flush so that we can do zone_verify
slave.flush()

# re-sign master and check that the re-sign made nothing
master.ctl("zone-sign")
after_update15 = master.zones_wait(zones, after_update, equal=False, greater=True)

t.xfr_diff(master, slave, zones, no_rrsig_rdata=True)
##for zone in zones:
##    slave.zone_verify(zone)

t.end()
