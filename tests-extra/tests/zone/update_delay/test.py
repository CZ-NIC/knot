#!/usr/bin/env python3

"""
Test of update delay.
"""

from dnstest.utils import *
from dnstest.test import Test
import random
import threading
import time

t = Test()

master = t.server("knot")
slave = t.server("knot")
zones = t.zone_rnd(2, records=10)

t.link(zones, master, slave)

master.update_delay = 6
slave.update_delay = 6

master.serial_policy = "unixtime"
slave.serial_policy = "unixtime"

for z in zones:
    master.zones[z.name].zfile.update_soa(serial=int(time.time()))
    slave.dnssec(z).enable = True # so that slave has own SOA serial management

def increment_serials(server, zones, serials):
    res = serials
    for z in zones:
        res[z.name] += server.update_delay
    return res

def zones_wait_eq(server, zones, serials):
    return server.zones_wait(zones, serials, greater=True, equal=True)

def send_update(up):
    try:
        up.try_send()
    except:
        pass

def send_up_bg(up):
    threading.Thread(target=send_update, args=[up]).start()

t.start()
serials = master.zones_wait(zones)
serials = zones_wait_eq(slave, zones, serials) # initial AXFR: without delay

for z in zones:
    up = master.update(z)
    up.add("test-update-delay-add", 3600, "A", "1.2.3.4")
    send_up_bg(up)

increment_serials(master, zones, serials)
serials = zones_wait_eq(master, zones, serials) # DDNS processing with delay

increment_serials(slave, zones, serials)
serials = zones_wait_eq(slave, zones, serials) # slave XFRs the zone swith another delay

t.end()
