#!/usr/bin/env python3

'''Test of freeze-thaw feature'''

from dnstest.test import Test
import threading

t = Test(tsig=False)

master = t.server("knot", xdp_enable=False) # DDNS over XDP not supported
slave = t.server("knot")

zone = t.zone("example.", storage=".")
t.link(zone, master, slave)

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

slave.ctl("zone-freeze")
t.sleep(1)

master.update_zonefile(zone, version=1)
master.reload()
master.zone_wait(zone, serial=2, equal=True)
t.sleep(1)

# check that slave freezed transfer after obtained notify
resp = slave.dig("added.example.", "A")
resp.check(rcode="NXDOMAIN", nordata="1.2.3.4")

slave.ctl("zone-refresh")

# check that slave transferred when invoked from ctl
slave.zone_wait(zone, serial=2, equal=True)
resp = slave.dig("added.example.", "A")
resp.check(rcode="NOERROR", rdata="1.2.3.4")

# check that update is refused after 8 queued
for i in range(10):
    up = slave.update(zone)
    up.add("freezedddns" + str(i), 3600, "A", "1.2.3.6")
    if i < 8:
        send_up_bg(up, "NOERROR")
    else:
        up.send("REFUSED")
    t.sleep(0.2)

master.update_zonefile(zone, version=2)
master.reload()
master.zone_wait(zone, serial=3, equal=True)
t.sleep(1)

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

for i in range(11):
    resp = slave.dig("freezedddns" + str(i) + ".example.", "A")
    if i == 8 or i == 9:
        resp.check(rcode="NXDOMAIN", nordata="1.2.3.6")
    else:
        resp.check(rcode="NOERROR", rdata="1.2.3.6")

t.stop()
