#!/usr/bin/env python3

'''Test zone expiration by master shutdown or broken AXFR.'''

from dnstest.test import Test
import time

def test_expire(zone, server):
    resp = server.dig(zone[0].name, "SOA")
    resp.check(rcode="SERVFAIL")

def break_xfrout(server):
    with open(server.confile, "r+") as f:
        config = f.read()
        f.seek(0)
        f.truncate()
        config = config.replace(" acl:", " #acl:")
        f.write(config)

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
break_xfrout(master)
master.update_zonefile(zone, version=1)
master.reload()

sub_slave.start()
sub_slave.zone_wait(zone)
remain = max(0, EXPIRE_SLEEP - int(time.time() - timer))
t.sleep(remain)
test_expire(zone, slave)
test_expire(zone, sub_slave) # both slaves expire at once despite sub_slave updated more recently. Thanks to EDNS Expire.
t.stop()
