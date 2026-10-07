#!/usr/bin/env python3

'''Test of catalog loading in a server reload.'''

from dnstest.test import Test

t = Test(tsig=False) # TSIG prevents zone_wait(catz)

master = t.server("knot")

master.conf_srv().background_workers = 2
master.conf_srv().async_start = True

t.start()
# Start an empty server, reconfigure it with a catalog zone, and reload.

catz = t.zone("catalog1.", storage=".")
bigz = t.zone_rnd(1, records=(44 if master.valgrind else 768), dnssec=False)
zones = catz + bigz

t.link(zones, master)

master.cat_interpret(catz[0])

master.conf_zone(bigz).zonefile_sync = -1

master.gen_confile()
master.reload()

master.zone_wait(catz)

t.sleep(10)
resp = master.dig("records.com.", "SOA")
resp.check(rcode="SERVFAIL")

t.end()
