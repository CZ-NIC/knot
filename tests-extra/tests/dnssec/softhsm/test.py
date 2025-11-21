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
zone = t.zone("example.com")
t.link(zone, knot1)
t.link(zone, knot2)

keys1 = KeystoreSoftHSM("keys1")
keys1.link(knot1)
keys2 = KeystoreSoftHSM("keys2")
keys2.link(knot2)

knot1.dnssec(zone).enable = True
knot1.dnssec(zone).keystore = [ keys1 ]

t.start()

knot1.zone_wait(zone)

backup_dir = os.path.join(knot1.dir, "backup")
knot1.ctl("zone-backup +keysonly +nokaspdb +nozonefile +nojournal +notimers +nocatalog +noquic +backupdir %s %s" %
          (backup_dir, zone[0].name), wait=True)

keys2.init(keys1)
knot2.ctl("zone-restore +keysonly +nokaspdb +nozonefile +nojournal +notimers +nocatalog +noquic +backupdir %s %s" %
          (backup_dir, zone[0].name), wait=True)

knot2.dnssec(zone).enable = True
knot2.dnssec(zone).keystore = [ keys2 ]
knot2.gen_confile()
knot2.reload()

knot2.zone_wait(zone)

t.end()
