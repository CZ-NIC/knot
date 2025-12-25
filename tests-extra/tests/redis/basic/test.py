#!/usr/bin/env python3

'''Test master-slave-like replication using Redis database.'''

import random
from dnstest.test import Test
from dnstest.utils import *

t = Test()

master = t.server("knot")
slave = t.server("knot")

zones = t.zone("example.com.")

t.link(zones, master)
t.link(zones, slave)

redis_master = t.backend("redis", tls=random.choice([True, False]))

master.db_out(zones, [redis_master], 1)
slave.db_in(zones, [redis_master], 1)

t.start()

master.zones_wait(zones)

# Test zone stored by master and loaded by slave
serials = slave.zones_wait(zones)
t.xfr_diff(master, slave, zones)

# Test incremental change stored by master and loaded by slave
for z in zones:
    up = master.update(z)
    up.add("suppnot1", 3600, "A", "1.2.3.4")
    up.delete("mail", "A", "192.0.2.3")
    up.send()

serials2 = slave.zones_wait(zones, serials)
t.xfr_diff(master, slave, zones) # AXFR diff
t.xfr_diff(master, slave, zones, serials) # IXFR diff
for z in zones:
    resp = slave.dig("suppnot1." + z.name, "A")
    resp.check(rcode="NOERROR", rdata="1.2.3.4")

# Test yet another incremental change
for z in zones:
    up = master.update(z)
    up.delete("suppnot1", "A", "1.2.3.4")
    up.add("suppnot1", 1800, "A", "1.2.3.5")
    up.send()

serials3 = slave.zones_wait(zones, serials2)
t.xfr_diff(master, slave, zones)
t.xfr_diff(master, slave, zones, serials)
t.xfr_diff(master, slave, zones, serials2)
for z in zones:
    resp = slave.dig("suppnot1." + z.name, "A")
    resp.check(rcode="NOERROR", nordata="1.2.3.4", rdata="1.2.3.5", ttl=1800)

# Test no change
uptodate_log_before = slave.log_search_count("database is up-to-date")
slave.ctl("zone-reload", wait=True)
uptodate_log_after = slave.log_search_count("database is up-to-date")
if uptodate_log_after - uptodate_log_before != len(zones):
    set_err("UP-TO-DATE LOGGED %dx" % uptodate_log)

# Add to DB manually. Slave will diverge from master.
for z in zones:
    txn = redis_master.cli("knot.upd.begin", z.name, master.conf_zone(z).zone_db_output)
    r = redis_master.cli("knot.upd.remove", z.name, txn, "example.com. 3600 in soa dns1.example.com. hostmaster.example.com. %d 10800 3600 1209600 7200" % serials3[z.name])
    r = redis_master.cli("knot.upd.add", z.name, txn, "example.com. 3600 in soa dns1.example.com. hostmaster.example.com. %d 10800 3600 1209600 7200" % (serials3[z.name] + 1))
    r = redis_master.cli("knot.upd.add", z.name, txn, "txtadd 3600 A 1.2.3.4")
    r = redis_master.cli("knot.upd.commit", z.name, txn)

    r = redis_master.cli("knot.upd.load", z.name, master.conf_zone(z).zone_db_output, str(serials3[z.name]))
    if not "txtadd" in r:
        set_err("NO TXTADD IN UPD")

serials4 = slave.zones_wait(zones, serials3)
for z in zones:
    resp = slave.dig("txtadd." + z.name, "A")
    resp.check(rcode="NOERROR", rdata="1.2.3.4")

# Update master with double SOA increment, it shall overwrite with greater serial and different contents.
for z in zones:
    up = master.update(z)
    up.add(z.name, 3600, "SOA", "dns1.example.com. hostmaster.example.com. %d 10800 3600 1209600 7200" % (serials3[z.name] + 2))
    up.delete("suppnot1", "A", "1.2.3.5")
    up.add("suppnot1", 900, "A", "1.2.3.5")
    up.send()

serials5 = slave.zones_wait(zones, serials4)
for z in zones:
    resp = slave.dig("txtadd." + z.name, "A")
    resp.check(rcode="NXDOMAIN", nordata="1.2.3.4")
    resp = slave.dig("suppnot1." + z.name, "A")
    resp.check(rcode="NOERROR", nordata="1.2.3.4", rdata="1.2.3.5", ttl=900)
t.xfr_diff(master, slave, zones)

# SOA serial logic rotation
serials6 = serials5

for i in range(5):
    if i == 3:
        slave.ctl("zone-freeze", wait=True)

    for z in zones:
        if i == 4:
            serials6[z.name] += 1
        else:
            serials6[z.name] += (1 << 30)
        serials6[z.name] %= (1 << 32)
        up = master.update(z)
        up.add(z.name, 3600, "SOA", "dns1 hostmaster %d 10800 3600 1209600 7200" % (serials6[z.name]))
        up.add("loop", 3600, "AAAA", "1::%d" % i)
        up.send()
    master.zones_wait(zones, serials6, equal=True)
    if i < 3:
        slave.zones_wait(zones, serials6, equal=True)

slave.ctl("zone-thaw")
slave.zones_wait(zones, serials6, equal=True)
t.xfr_diff(master, slave, zones)
resp = slave.dig("loop." + zones[0].name, "AAAA")
resp.check(rcode="NOERROR", rdata="1::1")
resp.check(rcode="NOERROR", rdata="1::4")
resp.check_count(5, "AAAA")

t.end()
