#!/usr/bin/env python3

'''Test of freeze-thaw feature'''

from dnstest.test import Test
from dnstest.utils import *
import threading

t = Test(tsig=False)

master = t.server("knot", xdp_enable=False) # DDNS over XDP not supported
slave = t.server("knot")

zone = t.zone("example.", storage=".")
big_zone = t.zone_rnd(1, records=(200 if slave.valgrind else 6000), dnssec=False)
t.link(zone + big_zone, master, slave)

slave.dnssec(big_zone).enable = True
slave.dnssec(big_zone).nsec3 = True
slave.dnssec(big_zone).nsec3_iters = 2000

def sleep_alt(time1, option=False, time2=None):
    if not option:
        t.sleep(time1)
    else:
        t.sleep(time2)

def send_update(up, err):
    up.send(err)

def send_up_bg(up, err):
    threading.Thread(target=send_update, args=[up, err]).start()

t.start()

master.zone_wait(zone)
slave.zone_wait(zone)

slave.ctl("zone-freeze " + zone[0].name)
t.sleep(1)
slave.ctl("zone-status")

master.update_zonefile(zone, version=1)
master.ctl("zone-reload " + zone[0].name)
master.zone_wait(zone, serial=2, equal=True)
t.sleep(1)
slave.ctl("zone-status")

# check that slave freezed transfer after obtained notify
resp = slave.dig("added.example.", "A")
resp.check(rcode="NXDOMAIN", nordata="1.2.3.4")

slave.ctl("zone-refresh")

# check that slave transferred when invoked from ctl
slave.zone_wait(zone, serial=2, equal=True)
resp = slave.dig("added.example.", "A")
resp.check(rcode="NOERROR", rdata="1.2.3.4")
slave.ctl("zone-status")

# check that update is refused after 8 queued
for i in range(10):
    up = slave.update(zone, allow_knsupdate=False)
    up.add("freezedddns" + str(i), 3600, "A", "1.2.3.6")
    if i < 8:
        send_up_bg(up, "NOERROR")
    else:
        up.send("REFUSED")
    t.sleep(0.2)
    slave.ctl("zone-status")

master.update_zonefile(zone, version=2)
master.ctl("zone-reload " + zone[0].name)
master.zone_wait(zone, serial=3, equal=True)
t.sleep(1)
slave.ctl("zone-status")

slave.ctl("zone-thaw")

# check that slave retransfered immediately after thaw
slave.zone_wait(zone, serial=3, equal=True)
resp = slave.dig("more.example.", "A")
resp.check(rcode="NOERROR", rdata="1.2.3.5")

# check that update works now
up = slave.update(zone)
up.add("freezedddns10", 3600, "A", "1.2.3.6")
up.send("NOERROR")
sleep_alt(2, master.valgrind, 4)
slave.ctl("zone-status")

for i in range(11):
    resp = slave.dig("freezedddns" + str(i) + ".example.", "A")
    if i == 8 or i == 9:
        resp.check(rcode="NXDOMAIN", nordata="1.2.3.6")
    else:
        resp.check(rcode="NOERROR", rdata="1.2.3.6")

# queued freezing and thawing
if not slave.valgrind: # otherwise unreliable, ctl thread sometimes stuck for 10+ secs, TODO debug
    serial = slave.zone_wait(big_zone)
    slave.ctl("zone-sign " + big_zone[0].name, wait=False)
    t.sleep(0.2)
    slave.ctl("zone-freeze", wait=False)
    t.sleep(0.2)
    if not "| freeze: freezing" in slave.ctl("zone-status " + big_zone[0].name, read_result=True):
        set_err("missing 'freezing' log")
    serial = slave.zone_wait(big_zone, serial)
    if not "| freeze: yes" in slave.ctl("zone-status " + big_zone[0].name, read_result=True):
        set_err("missing frozen zone log")
    slave.ctl("zone-sign " + big_zone[0].name, wait=False)
    t.sleep(0.2)
    slave.ctl("zone-thaw", wait=False)
    t.sleep(0.2)
    if not "| freeze: thawing" in slave.ctl("zone-status " + big_zone[0].name, read_result=True):
        set_err("missing 'thawing' log")
    serial = slave.zone_wait(big_zone, serial)

t.stop()
