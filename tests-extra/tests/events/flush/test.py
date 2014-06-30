#!/usr/bin/env python3

'''Test for flush event'''

from dnstest.utils import *
from dnstest.test import Test
import os

t = Test()

master = t.server("bind")
slave = t.server("knot")
slave.zonefile_sync = "3s"

zone = t.zone("example.")

t.link(zone, master, slave)
t.start()
slave.zone_wait(zone)

#check that the zone file has not been flushed
zone_path = slave.dir + "/slave/example.zone" 
if os.path.exists(zone_path):
    set_err("FLUSHED")

t.sleep(4)
if not os.path.exists(zone_path):
    set_err("NOT FLUSHED")

t.stop()

