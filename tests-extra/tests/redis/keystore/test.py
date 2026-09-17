#!/usr/bin/env python3

'''Test zone database as a keystore.'''

import random
from dnstest.test import Test
from dnstest.keystore import KeystoreRdb
from dnstest.utils import *

t = Test()

master = t.server("knot")

zone = t.zone("example.com.")
Z = zone[0].name

t.link(zone, master)

redis_master = t.backend("redis", tls=random.choice([True, False]))
keys = KeystoreRdb("keys", passwd=random.choice([None, "StrongPassword"]), key_label=random.choice([None, True]))

master.db_out(list(), [redis_master], 1)
master.dnssec(zone).keystore = [ keys ]
master.dnssec(zone).enable = True

t.start()

serial = master.zone_wait(zone)

t.end()
