#!/usr/bin/env python3

'''Test of Knot behavior when master has older SOA'''

from dnstest.test import Test

EXPIRE_SLEEP = 13
RESYNC_SLEEP = 7
TEST_START_EXPECTED = 4

t = Test()

master = t.server("knot")
slave = t.server("knot")

# this zone has refresh = 7s, retry = 7s and expire = 16s
zone = t.zone("example.", storage=".")
t.link(zone, master, slave)

master.disable_notify = True
slave.disable_notify = True

t.start()

# initial convenience check

master.zone_wait(zone)
slave.zone_wait(zone)

resp = slave.dig("added.example.", "A")
resp.check(rcode="NOERROR", rdata="1.2.3.4")

# check that slave ignored outdated master

master.update_zonefile(zone, version=1)
master.stop()
master.start()
t.sleep(RESYNC_SLEEP - TEST_START_EXPECTED)

resp = master.dig("added.example.", "A")
resp.check(rcode="NXDOMAIN")

resp = slave.dig("added.example.", "A")
resp.check(rcode="NOERROR", rdata="1.2.3.4")

# check that slave bootstrapped older zone

t.sleep(EXPIRE_SLEEP - RESYNC_SLEEP)

resp = slave.dig("added.example.", "A")
resp.check(rcode="NXDOMAIN")

t.stop()
