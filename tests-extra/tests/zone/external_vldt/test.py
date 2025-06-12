#!/usr/bin/env python3

"""
Test of external zone validation.
"""

from dnstest.utils import *
from dnstest.test import Test
import random

t = Test()

master = t.server("knot")
slave = t.server("knot")
zone = t.zone_rnd(1, records=40)
t.link(zone, master, slave)

def log_count_expect(server, pattern, expct):
    fnd = server.log_search_count(pattern)
    if fnd != expct:
        detail_log("LOG SEARCH COUNT '%s' found %d expected %d" % (pattern, fnd, expct))
        set_err("LOG SEARCH COUNT %d != %d" % (fnd, expct))

ZONE = zone[0].name
LOG = "for external validation"

slave.async_start = True
slave.zones[ZONE].external = True # TODO this will be a list or dict once 'external' secation has any fields

master.dnssec(zone[0]).enable = random.choice([False, True])

t.start()
serial = master.zone_wait(zone)

t.sleep(2)
log_count_expect(slave, LOG, 1)
resp = slave.dig(ZONE, "SOA")
resp.check(rcode="SERVFAIL")
resp.check_count(0, "SOA")

slave.ctl("zone-diff " + ZONE)
slave.ctl("zone-commit " + ZONE)
t.sleep(2)
resp = slave.dig(ZONE, "SOA")
resp.check_soa_serial(serial)

master.random_ddns(zone, allow_empty=False)
serial = master.zone_wait(zone, serial)

t.sleep(2)
log_count_expect(slave, LOG, 2)
slave.ctl("zone-abort " + ZONE)
t.sleep(2)
resp = slave.dig(ZONE, "SOA")
resp.check_soa_serial(serial - 1)

master.random_ddns(zone, allow_empty=False)
serial = master.zone_wait(zone, serial)

t.sleep(2)
log_count_expect(slave, LOG, 3)
slave.ctl("zone-diff " + ZONE)

slave.ctl("zone-commit " + ZONE)
t.sleep(2)
resp = slave.dig(ZONE, "SOA")
resp.check_soa_serial(serial)

slave.ctl("zone-freeze " + ZONE)
master.random_ddns(zone, allow_empty=False)
serial = master.zone_wait(zone, serial)

slave.zonemd_generate = "zonemd-sha512"
slave.gen_confile()
slave.ctl("zone-thaw " + ZONE)
t.sleep(1)
slave.reload()

master.random_ddns(zone, allow_empty=False)
serial = master.zone_wait(zone, serial)

t.sleep(2)
log_count_expect(slave, LOG, 5)
slave.ctl("zone-diff " + ZONE)
slave.ctl("zone-commit " + ZONE)
t.sleep(2)
resp = slave.dig(ZONE, "SOA")
resp.check_soa_serial(serial)

master.random_ddns(zone, allow_empty=False)
serial = master.zone_wait(zone, serial)

t.sleep(2)
log_count_expect(slave, LOG, 6)
slave.stop()
t.sleep(2)
log_count_expect(slave, "shutting down", 1)

t.end()
