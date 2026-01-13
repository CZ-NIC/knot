#!/usr/bin/env python3

'''Test for zone reload from Redis database.'''

import random
from dnstest.test import Test
from dnstest.utils import *

t = Test()

hidden = t.server("knot")
master = t.server("knot")
slave = t.server("knot")

zones = t.zone("example.com.", storage=".")

t.link(zones, hidden, master)
t.link(zones, master)
t.link(zones, slave)

tls = random.choice([True, False])
redis_master = t.backend("redis", tls=tls)
redis_slave = t.backend("redis", tls=tls)
redis_slave.slave_of(redis_master)

master.db_out(zones, [redis_master], 1)
slave.db_in(zones, [redis_slave], 1)

t.start()

# Check initial zone contents.
slave.zones_wait(zones)
t.xfr_diff(hidden, slave, zones)
resp = slave.dig("example.com", "TXT")
resp.check_record(section="answer", rtype="TXT", rdata="version1")

# Replace zone contents with serial unchanged.
hidden.update_zonefile(zones[0], version=1)
hidden.reload()
master.ctl("zone-retransfer")

# Check retransfered different zone contents with the same serial.
t.sleep(4)
t.xfr_diff(hidden, slave, zones)
resp = slave.dig("example.com", "TXT")
resp.check_record(section="answer", rtype="TXT", rdata="version2", nordata="version1")

t.end()
