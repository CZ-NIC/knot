#!/usr/bin/env python3

'''Test not blocking frequently updated zone1 by slow IXFR of zone2.'''

from dnstest.test import Test
from dnstest.utils import *
import random
import threading
import time

t = Test(tsig=False)

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

def slow_ixfr(server, zname, serial):
    server.kdig(zname, "IXFR=" + str(serial), msgdelay=MSGDELAY)

def send_update(up):
    try:
        up.try_send()
    except:
        pass

def send_up_bg(up):
    threading.Thread(target=send_update, args=[up]).start()

def check_blocked(server, zname):
    return server.log_search("[%s]" % zname, "blocked by")

t.start()

serial = master.zone_wait(zone_slow)
sfirst = serial
for i in range(12): # generating large enough IXFR so that it takes time to send
    master.ctl("zone-sign " + name_slow)
    serial = master.zone_wait(zone_slow, serial)

threading.Thread(target=slow_ixfr, args=[master, name_slow, sfirst]).start()

for i in range(5):
    owner = "abc" + str(i)

    upf = master.update(zone_freq)
    upf.add(owner, 3600, "A", "1.2.3.4")
    send_up_bg(upf)

    t.sleep(0.5)

    ups = master.update(zone_slow) # updating slow zone checks that it is still protected by locks by itself
    ups.add(owner, 3600, "A", "1.2.3.4")
    send_up_bg(ups)

    t.sleep(0.5)

    if not master.valgrind: # in valgrind mode, processing a DDNS may take more than 2 secs!
        resp = master.dig(owner + "." + name_freq, "A")
        resp.check(rcode="NOERROR", rdata="1.2.3.4")
    else:
        if check_blocked(master, name_freq):
            set_err("BLOCKED " + name_freq)

t.sleep(2)

if not check_blocked(master, name_slow):
    set_err("NOT BLOCKED " + name_slow)

# check zone_contents_deep_free() while an outgoing XFR is running

kd = threading.Thread(target=slow_ixfr, args=[master, name_slow, sfirst])
kd.start()
t.sleep(1)
if random.choice([False, True]):
    master.ctl("-f zone-purge +expire " + name_slow)
else:
    confsock = master.ctl_sock_rnd()
    master.ctl("conf-begin", custom_parm=confsock)
    master.ctl("conf-unset zone[%s]" % name_slow, custom_parm=confsock)
    master.ctl("conf-commit", custom_parm=confsock)
kd.join()

t.end()
