#!/usr/bin/env python3

'''Test of catalog loading within a server reload.'''

from dnstest.test import Test

t = Test(tsig=False) # TSIG prevents zone_wait(catz)

master = t.server("knot")

master.conf_srv().background_workers = 3
master.conf_srv().async_start = True

# Start an empty server, reconfigure it with catalog zones, and reload.
t.start()

catz0 = t.zone("catalog0.", storage=".")
catz1 = t.zone("catalog1.", storage=".")
catz2 = t.zone("catalog2.", storage=".")
catz3 = t.zone("catalog3.", storage=".")

zones = catz0 + catz1 + catz2 + catz3

t.link(zones, master)

master.cat_interpret(catz0[0])
master.cat_interpret(catz1[0])
master.cat_interpret(catz2[0])
master.cat_interpret(catz3[0])

master.gen_confile()
master.reload()

master.zones_wait(zones)

t.sleep(15) #  Provide plenty of time for all members to become configured.

# The catalog zones should be loaded and their members should be created by now.
resp = master.dig("records0.com.", "SOA")
resp.check(rcode="SERVFAIL")
resp = master.dig("records1.com.", "SOA")
resp.check(rcode="SERVFAIL")
resp = master.dig("records2.com.", "SOA")
resp.check(rcode="SERVFAIL")
resp = master.dig("records3.com.", "SOA")
resp.check(rcode="SERVFAIL")

t.end()
