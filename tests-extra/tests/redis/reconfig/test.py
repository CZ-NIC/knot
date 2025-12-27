#!/usr/bin/env python3

'''Test for Redis database reconfiguration.'''

import random
from dnstest.test import Test
from dnstest.utils import *

def db_upd(db, zone_name, inst, init=False):
    if init:
        txn = db.cli("knot.zone.begin", zone_name, str(inst))
        r = db.cli("knot.zone.store", zone_name, txn, "@ SOA dns mail 1 36000 600 864000 300")
        r = db.cli("knot.zone.commit", zone_name, txn)
    else:
        txn = db.cli("knot.upd.begin", zone_name, str(inst))
        r = db.cli("knot.upd.commit", zone_name, txn)

t = Test()

server = t.server("knot")

ZONE = "example.com."
zones = t.zone(ZONE)
t.link(zones, server)

redis1 = t.backend("redis", tls=random.choice([True, False]))
redis2 = t.backend("redis", tls=random.choice([True, False]))

server.db_in(zones, [redis1], 1)

t.start()

t.sleep(1)
db_upd(redis1, ZONE, 1, True)
db_upd(redis2, ZONE, 1, True)
db_upd(redis1, ZONE, 2, True)
db_upd(redis2, ZONE, 2, True)
serials = server.zones_wait(zones)

db_upd(redis1, ZONE, 1)
db_upd(redis2, ZONE, 1)
db_upd(redis1, ZONE, 2)
db_upd(redis2, ZONE, 2)
serials = server.zones_wait(zones, serials)

target_redis = random.choice([redis1, redis2])
target_inst  = random.choice([1, 2])

server.db_in(zones, [target_redis], target_inst)
server.gen_confile()
server.reload()

db_upd(target_redis, ZONE, target_inst)
serials = server.zones_wait(zones, serials)

t.end()
