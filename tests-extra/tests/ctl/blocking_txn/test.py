#!/usr/bin/env python3

'''Test deadlocking CTL with zone-begin and blocking zone-sign.'''

from dnstest.utils import *
from dnstest.test import Test
import random
import threading
import time

def background_sign(server, zone_name):
    try:
        server.ctl("-b zone-sign " + zone_name)
    except:
        pass

def run_thr(fun, server, zone_name):
    threading.Thread(target=fun, args=[server, zone_name]).start()

t = Test()

master = t.server("knot")
zones = t.zone_rnd(1, dnssec=False, records=40)
t.link(zones, master)

for z in zones:
    master.dnssec(z).enable = True

t.start()
serials = master.zones_wait(zones)
ZONE = zones[0].name

master.ctl("zone-begin " + ZONE)
run_thr(background_sign, master, ZONE)
t.sleep(1)
master.ctl("zone-abort " + ZONE)

t.sleep(1)
master.zones_wait(zones) # check if server is still sane
master.ctl("zone-status " + ZONE)

t.end()
