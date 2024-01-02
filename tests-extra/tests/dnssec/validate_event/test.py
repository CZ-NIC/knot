#!/usr/bin/env python3

'''Test for DNSSEC validation event'''

from dnstest.test import Test
from dnstest.utils import *

def dig_multi(server, zones, exp_rcode):
    for z in zones:
        resp = server.dig(z.name, "DNSKEY", dnssec=True)
        resp.check(rcode=exp_rcode)

t = Test()

master = t.server("knot")
slave = t.server("knot")
zones = t.zone("example.")

t.link(zones, master, slave, ixfr=True, ddns=True)

for z in zones:
    master.dnssec(z).enable = True
    master.dnssec(z).rrsig_lifetime = 10
    master.dnssec(z).rrsig_refresh = 1
    master.dnssec(z).rrsig_prerefresh = 1

t.start()

# SCENARIO I -- manual knotc zone-validate
serials = slave.zones_wait(zones)
serials = slave.zones_wait(zones, serials) # wait for first zone re-sign to demonstrate normal operation
master.stop()
slave.ctl("zone-validate", wait=True)
dig_multi(slave, zones, "NOERROR")
t.sleep(master.dnssec(z).rrsig_lifetime)
try:
    slave.ctl("zone-validate", wait=True)
    set_err("EXPIRED NOT FAILED")
except:
    pass
dig_multi(slave, zones, "SERVFAIL")

# SCENARIO II -- configured  dnssec-validation
master.start()
slave.stop()
for z in zones:
    slave.dnssec(z).validate = True
slave.gen_confile()
slave.start()
serials = slave.zones_wait(zones, serials)
serials = slave.zones_wait(zones, serials) # wait for first zone re-sign to demonstrate normal operation
master.stop()
dig_multi(slave, zones, "NOERROR")
t.sleep(master.dnssec(z).rrsig_lifetime + 1)
dig_multi(slave, zones, "SERVFAIL")

t.end()
