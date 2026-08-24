#!/usr/bin/env python3

'''Test non-apex SOA handling.'''

from dnstest.test import Test
from dnstest.utils import *
import filecmp
import os
import random
import shutil

t = Test()

master = t.server("knot")
slave = t.server("knot")

Z = "non.apex.soa.example."
zone = t.zone(Z, storage=".")

t.link(zone, master, slave)

master.conf_zone(zone).semantic_checks = False
master.dnssec(zone).enable = True

t.start()

master.zone_wait(zone)
master.ctl("zone-flush", wait=True)
slave.zone_wait(zone)
slave.ctl("zone-flush", wait=True)

if not filecmp.cmp(master.zones[Z].zfile.path, slave.zones[Z].zfile.path, shallow=False):
    set_err("ZONEFILES DIFFER")

t.end()
