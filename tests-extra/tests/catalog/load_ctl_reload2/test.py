#!/usr/bin/env python3

'''Test of catalog loading in a server reload (version 2).'''

from dnstest.test import Test

t = Test(tsig=False) # TSIG prevents zone_wait(catz)

master = t.server("knot")

master.conf_srv().background_workers = 2
master.conf_srv().async_start = True

t.start()
# Start an empty server, reconfigure it with a catalog zone, and reload.

catz = t.zone("catalog1.", storage=".")
bigz = t.zone_rnd(1, records=(44 if master.valgrind else 768), dnssec=False)
smallz = t.zone("example.")
zones = catz + bigz + smallz

t.link(zones, master)

master.cat_interpret(catz[0])

master.dnssec(bigz).enable = True
master.dnssec(bigz).nsec3 = True
master.dnssec(bigz).signing_threads = 1
master.dnssec(bigz).algorithm = "RSASHA512"

master.conf_zone(bigz).zonefile_sync = -1

if not master.valgrind:
    master.dnssec(bigz).zsk_size = 4096

master.gen_confile()
master.reload()

master.zone_wait(catz)
master.zone_wait(smallz)

master.zone_wait(bigz)
t.sleep(10)

# The catalog zone should be loaded and its members should be created by now.
resp = master.dig("records.com.", "SOA")
resp.check(rcode="SERVFAIL")

t.end()
