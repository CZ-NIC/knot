#!/usr/bin/env python3

'''Test for ALIAS resolving script.'''

import random
from dnstest.test import Test
from dnstest.utils import *

t = Test()

master = t.server("knot")
slave = t.server("knot")
ref = t.server("knot")

zones = t.zone("zone1", storage=".") + t.zone("zone2", storage=".")

t.link(zones, master)
t.link(zones, slave)
t.link(zones, ref)

redis = t.backend("redis", tls=random.choice([True, False]))

master.db_out(zones, [redis], 1)
slave.db_in(zones, [redis], 2)

ref.update_zonefile(zones[0], 10)
ref.update_zonefile(zones[1], 10)

if random.choice([True, False]):
    master.conf_zone(zones).journal_content = "all"
    master.conf_zone(zones).zonefile_load = "difference-no-serial"

slave.conf_zone(zones).zonefile_sync = "0"

t.start()

master.zones_wait(zones)
redis.unalias(1, 2)
redis.unalias(1, 2) # Should be NOOP.
serials = slave.zones_wait(zones)
t.xfr_diff(ref, slave, zones)

master.update_zonefile(zones[0], 1)
master.update_zonefile(zones[1], 1)
master.reload()
ref.update_zonefile(zones[0], 11)
ref.update_zonefile(zones[1], 11)
ref.reload()
redis.unalias(1, 2)
redis.unalias(1, 2) # Should be NOOP.
slave.zones_wait(zones, serials)
serials = slave.zones_wait(zones, serials)
t.xfr_diff(ref, slave, zones)

t.end()
