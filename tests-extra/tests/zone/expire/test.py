#!/usr/bin/env python3

'''Test zone expiration by master shutdown or broken AXFR.'''

from dnstest.test import Test

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

# this zone has refresh = 1s, retry = 1s and expire = 8s
zone = t.zone("example.", storage=".")
EXPIRE_SLEEP = 15

master = t.server("knot")
slave = t.server("knot")
slave.max_conn_idle = "1s"

t.link(zone, master, slave)

t.start()

master.zone_wait(zone)
slave.zone_wait(zone)

# expire by shutting down the master
master.stop()
t.sleep(EXPIRE_SLEEP);
test_expire(zone, slave)

# bring back master (notifies slave)
master.start()
master.zone_wait(zone)
slave.zone_wait(zone)

# expire by breaking AXFR
break_xfrout(master)
master.update_zonefile(zone, version=1)
master.reload()
t.sleep(EXPIRE_SLEEP);
test_expire(zone, slave)

t.stop()
