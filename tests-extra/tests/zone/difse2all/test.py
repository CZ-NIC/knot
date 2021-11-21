#!/usr/bin/env python3

"""
Test of difference-no-serial with changing journal-content.
"""

from dnstest.utils import *
from dnstest.test import Test
import random

t = Test()

# randomized different test scenarios
purge_beforehand = random.choice([True, False])
cold_reload = random.choice([True, False])
zone_reload_afterwards = random.choice([True, False])
detail_log("Scenario: purge_beforehand %s, cold_reload %s, zone_reload_afterwards %s" % (str(purge_beforehand), str(cold_reload), str(zone_reload_afterwards)))

knot = t.server("knot")
zone = t.zone("example.", storage=".")
t.link(zone, knot)
knot.dnssec(zone).enable = True
knot.zonefile_sync = "-1"

t.start()
serial = knot.zone_wait(zone)

knot.zones[zone[0].name].journal_content = "all"
knot.zonefile_load = "difference-no-serial"
if purge_beforehand:
    knot.ctl("zone-purge -f +expire example.")

knot.gen_confile()
if cold_reload:
    knot.stop()
    t.sleep(2)
    knot.start()
    knot.zone_wait(zone)
else:
    knot.reload()
    t.sleep(5)

if zone_reload_afterwards:
    knot.ctl("zone-reload")
    t.sleep(3)

knot.update_zonefile(zone, version=1)
knot.ctl("zone-reload")
knot.zone_wait(zone, serial)

t.end()
