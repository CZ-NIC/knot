#!/usr/bin/env python3

'''Test of EDNS expire based on RRSIG validity'''

from dnstest.test import Test
from dnstest.utils import *

t = Test()

master = t.server("knot")
slave = t.server("knot")
zones = t.zone("example.")

t.link(zones, master, slave, ixfr=True, ddns=True)

for z in zones:
    master.dnssec(z).enable = True
    master.dnssec(z).rrsig_lifetime = 20
    master.dnssec(z).rrsig_refresh = 1
    master.dnssec(z).rrsig_pre_refresh = 1

t.start()

serials = slave.zones_wait(zones)
serials = master.zones_wait(zones, serials) # wait for first re-sign
master.ctl("zone-freeze")
slave.ctl("zone-freeze")
t.sleep(master.dnssec(z).rrsig_lifetime + 1)
for z in zones:
    resp = slave.dig(z.name, "SOA", dnssec=True)
    resp.check(rcode="SERVFAIL")
    resp.check_count(0, rtype="RRSIG")
    if not slave.log_search("expired"):
         set_err("ZONE NOT EXPIRED")
slave.ctl("zone-thaw")
master.ctl("zone-thaw")
serials = slave.zones_wait(zones, serials)

slave.stop() # let slave dump current timerDB
slave.start()
slave.zones_wait(zones, serials) # wait for next re-sign and sync
master.stop()
slave.ctl("zone-backup +backupdir " + slave.dir + "/backup", wait=True)
slave.stop() # bug was: after backup, there is no timerDB dump
slave.start() # starts with obsolete expire timer

resp = slave.dig(z.name, "SOA", dnssec=True)
resp.check(rcode="NOERROR")
resp.check_count(1, "SOA")

t.end()
