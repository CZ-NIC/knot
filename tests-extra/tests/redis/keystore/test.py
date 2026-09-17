#!/usr/bin/env python3

'''Test zone database as a keystore.'''

import random
from dnstest.test import Test
from dnstest.keystore import KeystoreRdb
from dnstest.keys import Keymgr
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

_, out, _ = Keymgr.run_check(master.confile, "keys", "keystore-test")
count = 0
for line in out.splitlines():
    if line.startswith("ECDSAP256SHA256"):
        count += line.split().count("YES")
compare(8, count, "keystore-test YES count")

master.ctl(f"zone-freeze {Z}", wait=True)
master.ctl("zone-backup +backupdir " + master.dir + "/backup", wait=True)
redis_master.cli("FLUSHDB")
redis_master.cli("WAITOF 1 0 10")
master.ctl("zone-restore +backupdir " + master.dir + "/backup", wait=True)
master.ctl(f"zone-thaw {Z}", wait=True)
master.ctl(f"zone-sign {Z}", wait=True)
master.zone_wait(zone, serial)

t.end()
