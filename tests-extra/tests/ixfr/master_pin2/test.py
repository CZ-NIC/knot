#!/usr/bin/env python3

'''Test of master pinning using serial shift.'''

import os
import random
import threading
import time
from dnstest.test import Test
from dnstest.utils import *

PIN = 5
RUNNING = True

t = Test(address=4, tsig=False)

masterA = t.server("knot", address="127.0.0.2", via=True)
masterB = t.server("knot", address="127.0.0.3", via=True)
slave = t.server("knot", address="127.0.0.4", via=True)
zones = t.zone("example.")
zone = zones[0]

def send_update(up):
    try:
        up.try_send()
    except:
        pass

def send_up_bg(up):
    threading.Thread(target=send_update, args=[up]).start()

def updating():
    i = 0
    while RUNNING:
        for s in [masterA, masterB]:
            up = s.update(zone)
            up.add("xxx" + str(i), i, "A", "1.2.3." + str(i))
            send_up_bg(up)
            t.sleep(1)
            i = i + 1

def check_cur(expec, unexp):
    resp = slave.dig("server.name." + zone.name, "TXT")
    resp.check(rcode="NOERROR", rdata=expec.name, nordata=unexp.name)

t.link(zones, masterA, slave, ixfr=True)
t.link(zones, masterB, slave, ixfr=True)

for m in [ masterA, masterB ]:
    m.conf_zone(zones).serial_policy = "unixtime"
    m.conf_zone(zones).zonefile_load = "difference-no-serial"
    m.dnssec(zones).enable = True
    m.conf_zone(zones).journal_content = "all"

masterA.conf_zone(zones).notify_delay = "0"  # Disable even the small random value tests use.
masterB.conf_zone(zones).notify_delay = "0"  #
masterB.conf_zone(zones).serial_modulo = str(-PIN)

t.start()

ma_serials0 = masterA.zones_wait(zones)
mb_serials0 = masterB.zones_wait(zones)
slave.zones_wait(zones)

# Align the masters before the testing starts.
slave.ctl("zone-freeze", wait=True)
serials0 = slave.zones_wait(zones)
masterA.ctl("zone-sign")
masterB.ctl("zone-sign")
masterA.zones_wait(zones, ma_serials0)
masterB.zones_wait(zones, mb_serials0)
slave.ctl("zone-thaw")

serials0 = slave.zones_wait(zones, serials0)

for m in [ masterA, masterB ]:
    up = m.update(zone)
    up.add("server.name", 3600, "TXT", m.name)
    up.send()

serials0 = slave.zones_wait(zones, serials0)

threading.Thread(target=updating, args=[]).start()

check_cur(masterA, masterB)

masterA.ctl("zone-freeze")

t.sleep(PIN + 4)

check_cur(masterB, masterA)

masterA.ctl("zone-thaw")

t.sleep(4)

# May fail occasionally, for details see this commit's message.
check_cur(masterA, masterB)

RUNNING = False

t.sleep(4)

t.end()
