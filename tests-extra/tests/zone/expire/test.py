#!/usr/bin/env python3

'''Test zone expiration by master shutdown or broken AXFR.'''

from dnstest.test import Test
import time

def test_status(zone, server, status):
    resp = server.dig(zone[0].name, "SOA")
    resp.check(rcode=status)

def test_expire(zone, server):
    test_status(zone, server, "SERVFAIL")

def test_not_expired(zone, server):
    test_status(zone, server, "NOERROR")

def break_xfrout(server, zone):
    server.ctl("zone-xfr-freeze %s" % zone[0].name, wait=True)

def fix_xfrout(server, zone):
    server.ctl("zone-xfr-thaw %s" % zone[0].name, wait=True)

t = Test(tsig=False)

# this zone has refresh = 2s, retry = 2s and expire = 16s
zone = t.zone("example.", storage=".")
EXPIRE_SLEEP = 18

master = t.server("knot")
slave = t.server("knot")
sub_slave = t.server("knot")
slave.tcp_remote_io_timeout = "1000"

t.link(zone, master, slave)
t.link(zone, slave, sub_slave)

slave.zones[zone[0].name].expire_min = 16
sub_slave.zones[zone[0].name].expire_min = 16

t.start()

master.zone_wait(zone)
slave.zone_wait(zone)
sub_slave.zone_wait(zone)
sub_slave.stop()

# expire by shutting down the master
master.stop()
t.sleep(EXPIRE_SLEEP);
test_expire(zone, slave)

# bring back master (notifies slave)
master.start()
master.zone_wait(zone)
slave.zone_wait(zone)
timer = time.time()

# expire by breaking AXFR
break_xfrout(master, zone)
master.update_zonefile(zone, version=1)
master.ctl("zone-reload example.")

sub_slave.start()
sub_slave.zone_wait(zone)
remain = max(0, EXPIRE_SLEEP - int(time.time() - timer))
t.sleep(remain)
test_expire(zone, slave)
test_expire(zone, sub_slave) # both slaves expire at once despite sub_slave updated more recently. Thanks to EDNS Expire.

# Test for expiration prolonging via EDNS (RFC 7314, section 4, second paragraph).
# 1) Test expiration prolonging by EDNS Expire in SOA query responses.

# bring back the servers once more and reset the expire timers
fix_xfrout(master, zone)
slave.ctl("zone-refresh", wait=True)
sub_slave.zone_wait(zone)

# disallow actual updates from slave, SOA queries are still allowed
break_xfrout(slave, zone)

# let the original expire timer (without EDNS) on sub_slave run out
t.sleep(2 * EXPIRE_SLEEP)

# the expire timer on sub_slave should be kept prolonged just by SOA queries
test_not_expired(zone, slave)
test_not_expired(zone, sub_slave)

# 2) Test that the expire timer in sub_slave isn't directly set to
# shorter EDNS Expire received in SOA query responses. Simulate an
# expire timer difference (normally caused by multi-path propagation)
# by lowering the expire value while keeping the serial.
master.ctl("zone-begin example.")
master.ctl("zone-set example. example. 1200 SOA ns admin 4242 2 2 5 600")
master.ctl("zone-commit example.")
fix_xfrout(slave, zone)
t.sleep(1)
slave.ctl("zone-refresh", wait=True)     # SOA query only, same serial
sub_slave.ctl("zone-refresh", wait=True) # SOA query only, same serial
slave.stop()

t.sleep(8)

# the new expire (5 seconds) from slave would have run out on sub_slave,
# but the original expire timer (started as 16 seconds) has been retained
test_not_expired(zone, sub_slave)

t.sleep(8)

# the original expire time has finally run out
test_expire(zone, sub_slave)

t.stop()
