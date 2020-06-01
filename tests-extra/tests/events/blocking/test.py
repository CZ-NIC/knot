#!/usr/bin/env python3

'''Test of freeze-thaw feature'''

from dnstest.test import Test
from dnstest.utils import *

t = Test(tsig=False)

master = t.server("knot")

zone = t.zone_rnd(1, records=300, dnssec=False)
t.link(zone, master)

master.dnssec(zone[0]).enable = True

def soa_rrsig(server, zones):
    resp = server.dig(zones[0].name, "SOA", dnssec=True)
    return resp.resp.answer[1].to_rdataset()[0].to_text()

master.ctl_params_append = ["-t", "35"]

t.start()

master.zone_wait(zone)

rrsig0 = soa_rrsig(master, zone)

master.ctl("zone-sign") # non-blocking

rrsig1 = soa_rrsig(master, zone)
if rrsig1 != rrsig0:
    set_err("Test failure.")

master.ctl("zone-sign", wait=True) # blocking re-sign

rrsig2 = soa_rrsig(master, zone)
if rrsig2 == rrsig1:
    set_err("Not re-signed before re-query.")

master.ctl("zone-sign") # non-blocking
master.ctl("zone-freeze", wait=True) # followed by blocking freeze

rrsig3 = soa_rrsig(master, zone)
if rrsig3 == rrsig2:
    set_err("Not freezed before re-query.")

master.ctl("zone-thaw")

t.stop()
