#!/usr/bin/env python3

'''Test of high availability using Redis replication with the sentinel mode.'''

import random
from dnstest.test import Test
from dnstest.utils import *

t = Test()

master = t.server("knot")
slave1 = t.server("knot")
slave2 = t.server("knot")

ZONE = "example.com"
zones = t.zone(ZONE, storage=".")

t.link(zones, master)
t.link(zones, slave1)
t.link(zones, slave2)

freeze_kill = random.choice([True, False])
tls = random.choice([True, False])
redis_sentinel = t.backend("redis", tls=tls)
redis_master = t.backend("redis", tls=tls)
redis_slave1 = t.backend("redis", tls=tls)
redis_slave2 = t.backend("redis", tls=tls)

redis_slave1.slave_of(redis_master)
redis_slave2.slave_of(redis_master)
redis_sentinel.sentinel_of(redis_master, 1)

zone_write_instances = random.choice([
    [redis_sentinel],
    [redis_master, redis_slave1, redis_slave2],
    [redis_sentinel, redis_master, redis_slave1, redis_slave2]
])
master.db_out(zones, zone_write_instances, 1)
slave1.db_in(zones,  [redis_slave1], 1)
slave2.db_in(zones,  [redis_slave1, redis_slave2], 1)

t.start()

# Give sentinel some time to discover the replicas
t.sleep(10)

# Initial synchronization
serial_init = slave1.zones_wait(zones)
serial = slave2.zones_wait(zones)
# serial == serial_init now

# Update master, wait for for replicas
master.ctl(f"zone-serial-set {ZONE} +1")
slave1.zones_wait(zones, serial)
serial = slave2.zones_wait(zones, serial)

# Update replica2/new_master - original master is down
redis_slave1.stop() # Ensure replica2 becomes a new master
redis_master.stop()
t.sleep(1)
for i in range(10): # usualy just 2x
    try:
        master.ctl(f"zone-serial-set {ZONE} +1")
    except Exception:
        t.sleep(2)
        continue
    break
slave2.zones_wait(zones, serial)
redis_slave1.start() # Put replica2 into operation
serial = slave1.zones_wait(zones, serial)

# Clog replica2/new_master and update new master to replica1
if freeze_kill:
    redis_slave2.freeze(20).wait()
else:
    redis_slave2.stop(kill=True)
    t.sleep(20)
    redis_slave2.start()
redis_slave1.run_monitor()
redis_slave2.run_monitor()
master.ctl(f"zone-serial-set {ZONE} +1")
slave1.zones_wait(zones, serial)
serial = slave2.zones_wait(zones, serial)

t.xfr_diff(master, slave1, zones, serial_init)
t.xfr_diff(master, slave2, zones, serial_init)

# Add to DB manually.
slave2.db_in(zones,  [redis_slave2], 1)
slave2.gen_confile()
slave2.reload()
slave2.zones_wait(zones) # interesting: remove and see
txn = redis_slave1.cli("knot.upd.begin", ZONE, "1")
redis_slave1.cli("knot.upd.add", ZONE, txn, "test TXT test")
redis_slave1.cli("knot.upd.commit", ZONE, txn)
slave1.zones_wait(zones, serial)
serial = slave2.zones_wait(zones, serial)

t.xfr_diff(slave1, slave2, zones, serial_init)

# Gather some information from replica2.
redis_slave2.cli("XREAD", "BLOCK", "50", "STREAMS", b"k\x01\x01", "0-0")
redis_slave2.cli("KNOT.ZONE.INFO", ZONE)

t.end()
