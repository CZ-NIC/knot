#!/usr/bin/env python3

'''Test of turning on signing on already running slave.'''

from dnstest.utils import *
from dnstest.test import Test
import shutil
import random

t = Test()

master = t.server("knot")
slave  = t.server("knot")

zone = t.zone("example.") # has SOA serial lower than @now

t.link(zone, master, slave, ddns=True)

master.serial_policy = random.choice(["increment", "unixtime", "dateserial"])
slave.serial_policy = random.choice(["increment", "unixtime", "dateserial"])

slave.dnssec(zone).nsec3 = random.choice([False, True])

slave.zonefile_load = random.choice(["none", "whole"])
for z in zone:
    slave.zones[z.name].journal_content = random.choice(["all", "none", "changes"])

cold_reload = random.choice([False, True])
if slave.zonefile_load == "none" and slave.zones[zone[0].name].journal_content != "all":
    cold_reload = False

t.start()

serial = slave.zone_wait(zone)

slave.dnssec(zone).enable = True
slave.gen_confile()

if cold_reload:
    slave.stop()
    t.sleep(2)
    slave.start()
    serial = slave.zone_wait(zone)
else:
    slave.reload()
    serial = slave.zone_wait(zone, serial)

slave.ctl("-f -b zone-flush")
slave.zone_verify(zone)

t.sleep(2)
up = master.update(zone)
up.add("hjk.%s" % zone[0].name, 3600, "TXT", "hjk")
up.send()

slave.zone_wait(zone, serial)
slave.ctl("-f -b zone-flush")
slave.zone_verify(zone)

t.end()
