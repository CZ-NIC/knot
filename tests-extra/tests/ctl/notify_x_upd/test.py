#!/usr/bin/env python3

'''Test of crash when NOTIFY or flush is executed during zone CTL update.'''

from dnstest.utils import *
from dnstest.test import Test
import random
import threading
import time
import os

scenario_flush = random.choice([False, True])

loop_stop = False

def background_notify(server, zone_name):
    global scenario_flush
    try:
        if scenario_flush:
            server.ctl("-f zone-flush " + zone_name)
        else:
            server.ctl("zone-notify " + zone_name)
    except:
        pass

def background_notify_loop(server, zone_name):
    global loop_stop
    while not loop_stop:
        background_notify(server, zone_name)

def run_thr(fun, server, zone_name):
    threading.Thread(target=fun, args=[server, zone_name]).start()

t = Test()

master = t.server("knot")
slave = t.server("knot")
zones = t.zone_rnd(1, dnssec=False, records=800)
t.link(zones, master, slave)
ZONE = zones[0].name

t.start()
serials = slave.zones_wait(zones)

try:
    run_thr(background_notify_loop, master, ZONE)

    for i in range(10):
        master.ctl("zone-begin " + ZONE)
        master.ctl("zone-set %s zzzzzzzzzzzzzz%d 3600 A 1.2.3.%d" % (ZONE, i + 1, i + 1))
        if i > 0:
            master.ctl("zone-unset %s zzzzzzzzzzzzzz%d A" % (ZONE, i))
        master.ctl("zone-commit " + ZONE)
finally:
    loop_stop = True

t.end()
