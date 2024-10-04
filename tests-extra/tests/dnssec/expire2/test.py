#!/usr/bin/env python3

'''Test of EDNS expire based on RRSIG validity if when signing up-to-date'''

from dnstest.test import Test
from dnstest.utils import *

t = Test()

master = t.server("knot")
slave = t.server("knot")
zones = t.zone("example.com", storage=".")

t.link(zones, master, slave, ixfr=True, ddns=True)

for z in zones:
    master.dnssec(z).enable = True
    master.dnssec(z).rrsig_lifetime = 40
    master.dnssec(z).rrsig_refresh = 5
    master.dnssec(z).rrsig_prerefresh = 0
    master.dnssec(z).propagation_delay = 0

def send_ddns(server, zone, data):
    up = server.update(zone)
    up.delete("test." + zone.name, "TXT")
    up.add("test." + zone.name, 2, "TXT", data)
    up.send("NOERROR")

t.start()

master.zones_wait(zones)
send_ddns(master, zones[0], "init")
master.ctl("zone-sign", wait=True)

t.sleep(20)
send_ddns(master, zones[0], "first")

t.sleep(20)
send_ddns(master, zones[0], "second")

t.sleep(22)

soa = slave.dig(zones[0].name, "SOA")
soa.check(rcode="NOERROR")

if slave.log_search("expired"):
    set_err("ZONE EXPIRED")

t.end()
