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
password = random.choice([None, "StrongPassword"]) if not master.valgrind else None
keys = KeystoreRdb("keys", passwd=password, key_label=random.choice([None, True]), rdb=redis_master)
PEM_HDR = "-----BEGIN ENCRYPTED PRIVATE KEY" if password else "-----BEGIN PRIVATE KEY"

master.db_out(list(), [redis_master], 1)
master.dnssec(zone).keystore = [ keys ]
master.dnssec(zone).enable = True

t.start()

serial = master.zone_wait(zone)

db_key_ids = keys.keys(True)
for id in db_key_ids:
    pem = redis_master.cli("GET", id)
    isset(PEM_HDR in pem, "database PEM header")

_, out, _ = Keymgr.run_check(master.confile, "keys", "keystore-test")
count = 0
for line in out.splitlines():
    if line.startswith("ECDSAP256SHA256"):
        count += line.split().count("YES")
compare(8, count, "keystore-test YES count")

master.ctl(f"zone-freeze {Z}", wait=True)
master.ctl(f"zone-backup +backupdir {master.dir}/backup", wait=True)

key_ids = keys.keys(False)
for id in key_ids:
    file_name = f"{master.dir}/backup/keys/keys/{id}.pem"
    with open(file_name, "r") as f:
        isset(f.readline().startswith(PEM_HDR), "backup PEM header")

keys.clear()

master.ctl(f"zone-restore +backupdir {master.dir}/backup", wait=True)
master.ctl(f"zone-thaw {Z}", wait=True)
master.ctl(f"zone-sign {Z}", wait=True)
master.zone_wait(zone, serial)

db_key_ids = keys.keys(True)
for id in db_key_ids:
    pem = redis_master.cli("GET", id)
    isset(PEM_HDR in pem, "database PEM header")

t.end()
