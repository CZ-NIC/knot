#!/usr/bin/env python3

'''Test of ZONEMD verification and generation.'''

from dnstest.test import Test
import random

t = Test()

master = t.server("knot")
slave = t.server("knot")
zone = t.zone("example.", storage=".")

t.link(zone, master, slave)

slave.dnssec(zone).enable = True

master.zonemd_verify = True
slave.zonemd_verify = True
slave.zonemd_generate = random.choice(["zonemd-sha384", "zonemd-sha512"])

t.start()

serial = master.zone_wait(zone)
slave.zone_wait(zone, serial, equal=True, greater=False)

if slave.zonemd_generate == "zonemd-sha384": # otherwise dnssec-verify bug
    slave.zone_backup(zone, flush=True)
    slave.zone_verify(zone)

t.end()
