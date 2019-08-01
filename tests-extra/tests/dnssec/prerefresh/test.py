#!/usr/bin/env python3

'''Test for batch pre-refresh of RRSIGs.'''

from dnstest.utils import *
from dnstest.test import Test

t = Test()

master = t.server("knot")
zone = t.zone("example.com.")
t.link(zone, master)

master.dnssec(zone).enable = True
master.dnssec(zone).rrsig_lifetime = 20
master.dnssec(zone).rrsig_refresh = 2
master.dnssec(zone).rrsig_prerefresh = 4

t.start()

serial_init = master.zone_wait(zone)

master.ctl("zone-sign")

t.sleep(2)

up = master.update(zone)
up.add("record1.example.com.", 3600, "A", "1.2.3.4")
up.send("NOERROR")

serial_updates = master.zone_wait(zone)

serial_refresh = master.zone_wait(zone, serial_updates)

t.sleep(10)

serial_wait = master.zone_wait(zone)

if serial_wait != serial_refresh:
    set_err("RRSIGs refreshed separately (%d != %d)" % (serial_wait, serial_refresh))

t.stop()
