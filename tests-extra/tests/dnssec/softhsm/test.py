#!/usr/bin/env python3

"""
Backup and restore of SoftHSM keystores.
"""

from dnstest.utils import *
from dnstest.keystore import KeystoreSoftHSM
from dnstest.test import Test

t = Test()

knot1 = t.server("knot")
knot2 = t.server("knot")
zone = t.zone("example.com") + t.zone_rnd(5)
t.link(zone, knot1)
t.link(zone, knot2)

keys1 = KeystoreSoftHSM("keys1")
keys1.link(knot1)
keys2 = KeystoreSoftHSM("keys2")
keys2.link(knot2)

knot1.dnssec(zone).enable = True
knot1.dnssec(zone).keystore = [ keys1 ]

t.start()

# Wait for signed zone
knot1.zone_wait(zone[0])
resp = knot1.dig(zone[0].name, "DNSKEY")
resp.check_count(2, "DNSKEY")

# Wait for unsigned zone
serial = knot2.zone_wait(zone[0])
resp = knot2.dig(zone[0].name, "DNSKEY")
resp.check_count(0, "DNSKEY")

backup_dir = os.path.join(knot1.dir, "backup")
knot1.ctl("zone-backup +keysonly +backupdir %s %s" % (backup_dir, zone[0].name), wait=True)

keys2.init(keys1) # Synchronize tokens directory between SoftHSMs
knot2.ctl("zone-restore +keysonly +backupdir %s %s" % (backup_dir, zone[0].name), wait=True)

# Enable signing with initial keys from the backup
knot2.dnssec(zone).enable = True
knot2.dnssec(zone).keystore = [ keys2 ]
knot2.gen_confile()
knot2.reload()

# Check the keysets match
knot2.zone_wait(zone[0], serial)
resp = knot2.dig(zone[0].name, "DNSKEY")
resp.cmp(knot1)

t.end()
