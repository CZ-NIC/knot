#!/usr/bin/env python3

'''Trigger replan_load_updated on slave where nothing is to be loaded (journal, zonefile) and verify re-planning DNSSEC.'''

import random
from dnstest.test import Test
from dnstest.utils import *

SCENARIO = random.choice([1, 2])
detail_log("SCENARIO %d" % SCENARIO)

t = Test()

master = t.server("knot")
slave = t.server("knot")
zone = t.zone_rnd(1, dnssec=False, records=10)
t.link(zone, master, slave)
ZONE = zone[0].name

for z in zone:
    slave.dnssec(z).enable = True
    slave.dnssec(z).nsec3 = True
    slave.dnssec(z).nsec3_salt_len = 0
    slave.dnssec(z).rrsig_lifetime = 25 if SCENARIO == 1 else 20
    slave.dnssec(z).rrsig_refresh = 5
    slave.dnssec(z).rrsig_prerefresh = 1
    slave.dnssec(z).zone_max_ttl = 4
    slave.zones[z.name].journal_content = "all"
slave.zonefile_sync = "-1"
slave.zonefile_load = "none"
slave.zonemd_generate = "zonemd-sha384"

t.start()

slave.zones_wait(zone)

if SCENARIO == 1:
    slave.ctl("-f zone-flush")
    slave.stop()
    t.sleep(2)
    slave.start()
    slave.zones_wait(zone)

if SCENARIO == 2:
    slave.zonemd_generate = "zonemd-sha512"
    slave.gen_confile()

slave.ctl("reload")

t.sleep(20)

slave.ctl("-f zone-flush", wait=True)
slave.zone_verify(zone)

t.end()
