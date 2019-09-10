#!/usr/bin/env python3

'''Test of freeze-thaw feature'''

from dnstest.test import Test
from dnstest.utils import *
import threading

t = Test(tsig=False)

master = t.server("knot")

zone = t.zone_rnd(1, records=200, dnssec=False)
t.link(zone, master)

master.dnssec(zone[0]).enable = True

def soa_rrsig(server, zones):
    resp = server.dig(zones[0].name, "SOA", dnssec=True)
    return resp.resp.answer[1].to_rdataset()[0].to_text()

t.start()

master.zone_wait(zone)

rrsig0 = soa_rrsig(master, zone)

master.ctl("zone-sign") # non-blocking

rrsig1 = soa_rrsig(master, zone)
if rrsig1 != rrsig0:
    set_err("Test failure.")

master.ctl("-b zone-sign") # blocking re-sign

rrsig2 = soa_rrsig(master, zone)
if rrsig2 == rrsig1:
    set_err("Not re-signed before re-query.")

master.ctl("zone-sign") # non-blocking
master.ctl("-b zone-freeze") # followed by blocking freeze

rrsig3 = soa_rrsig(master, zone)
if rrsig3 == rrsig2:
    set_err("Not freezed before re-query.")

master.ctl("zone-thaw")

# final challenge: two queued blocking events

def blocking_resign(server):
    server.ctl("-b zone-sign", availability=False)

event1 = threading.Thread(target=blocking_resign, args=(master, ), kwargs={})
event1.start()
event2 = threading.Thread(target=blocking_resign, args=(master, ), kwargs={})
event2.start()

rrsig4 = soa_rrsig(master, zone)
if rrsig4 != rrsig3:
    set_err("Test thread failure.")

event1.join()

rrsig5 = soa_rrsig(master, zone)
if rrsig5 == rrsig4:
    set_err("Not re-signed before join1.")

event2.join()

rrsig6 = soa_rrsig(master, zone)
if rrsig6 == rrsig5:
    set_err("Not re-signed before join2.")

t.stop()
