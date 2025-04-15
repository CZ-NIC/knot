#!/usr/bin/env python3

'''Test not blocking frequently updated zone1 by slow IXFR of zone2.'''

from dnstest.test import Test
import random
import threading
import time

t = Test(tsig=False, stress=False) # FIXME stress

master = t.server("knot")
zone_slow = t.zone(".")
name_slow = zone_slow[0].name
zone_freq = t.zone("example.")
name_freq = zone_freq[0].name
zones = zone_slow + zone_freq
t.link(zones, master)
master.dnssec(zone_slow).enable = True

MSGDELAY = 90

master.tcp_remote_io_timeout = 4000
master.tcp_io_timeout = 4000

def slow_ixfr(server, zname, seria):
    server.kdig(zname, "IXFR=" + str(seria), msgdelay=MSGDELAY)

def send_update(up):
    try:
        up.try_send()
    except:
        pass

def send_up_bg(up):
    threading.Thread(target=send_update, args=[up]).start()

t.start()

serial = master.zone_wait(zone_slow)
sfirst = serial
for i in range(12): # generating large enough IXFR so that it takes time to send
    master.ctl("zone-sign " + name_slow)
    serial = master.zone_wait(zone_slow, serial)

threading.Thread(target=slow_ixfr, args=[master, name_slow, sfirst]).start()

for i in range(5):
    upf = master.update(zone_freq)
    upf.add("abc" + str(i), 3600, "A", "1.2.3.4")
    send_up_bg(upf)

    ups = master.update(zone_slow) # updating slow zone checks that it is still protected by locks by itself
    ups.add("abc" + str(i), 3600, "A", "1.2.3.4")
    send_up_bg(ups)

    t.sleep(1.4 if master.valgrind else 1)
    q = master.dig("abc" + str(i) + "." + name_freq, "A")
    q.check(rcode="NOERROR", rdata="1.2.3.4")

t.sleep(2)

t.end()
