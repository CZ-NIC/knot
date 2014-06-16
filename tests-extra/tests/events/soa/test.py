#!/usr/bin/env python3

'''Test to end all tests'''

from dnstest.utils import *
from dnstest.test import Test

EXPIRE_SLEEP = 5

def test_refresh(slave):
    resp = slave.dig("example.", "SOA")
    resp.check(rcode="NOERROR")
    t.sleep(EXPIRE_SLEEP)
    resp = slave.dig("example.", "SOA")
    resp.check(rcode="NOERROR")
    
def test_expire(slave):
    resp = slave.dig("example.", "SOA")
    resp.check(rcode="NOERROR")
    t.sleep(EXPIRE_SLEEP)
    resp = slave.dig("example.", "SOA")
    resp.check(rcode="SERVFAIL")

t = Test()

master = t.server("bind")
slave = t.server("knot")
slave.max_conn_idle = "1s"

# this zone has refresh = 1s, retry = 1s and expire = 1s + 2s for connection timeouts
zone = t.zone("example.", storage=".")

t.link(zone, master, slave)

t.start()

slave.zone_wait(zone)
#test that zone does not expire when master is alive
test_refresh(slave)
master.stop()
#test that zone does expire when master is down
test_expire(slave)

#update master zone file with 10s refresh in SOA
master.update_zonefile(zone, version=1)
master.start()

slave.zone_wait(zone) #this has to work - retry is 1s
slave.flush()

#zone should expire, because refresh < expire
test_expire(slave)

#switch server roles, slave becomes master - there should be no expire
master.stop()
slave.zones = {}
master.zones = {}
t.link(zone, slave)
t.generate_conf()
slave.reload()

slave.zone_wait(zone)
t.sleep(EXPIRE_SLEEP)
slave.zone_wait(zone)

#switch again - zone should expire now
slave.zones = {}
t.link(zone, master, slave)
t.generate_conf()
slave.reload()

test_expire(slave)

t.stop()

