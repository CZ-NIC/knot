#!/usr/bin/env python3

"""
Check of DNSSEC keys purging.
"""

import os
import random
import shutil
from dnstest.utils import *
from dnstest.keys import Keymgr
from dnstest.keystore import KeystorePEM, KeystoreSoftHSM
from dnstest.test import Test

def check_key_count(server, keystore, expected):
    try:
        files = len([name for name in os.listdir(keystore.config() if keystore else
                                                 os.path.join(server.keydir, "keys"))])
    except FileNotFoundError:
        files = 0
    compare(files, expected, "privkey count in %s" % keystore.id if keystore else "Default")

t = Test()

server = t.server("knot")
zones = t.zone_rnd(3)
t.link(zones, server)

kstore_dflt = None  # Default keystore.
kstore_pem = KeystorePEM("keys1")
#kstore_hsm = KeystoreSoftHSM("keys2")

server.dnssec(zones[0]).enable = True
server.dnssec(zones[0]).propagation_delay = 1
# Default keystore for zones[0].

server.dnssec(zones[1]).enable = True
server.dnssec(zones[1]).propagation_delay = 1
server.dnssec(zones[1]).keystore = [ kstore_pem ]

t.start()
serial = server.zones_wait(zones)

check_key_count(server, kstore_dflt, 2)
check_key_count(server, kstore_pem, 2)

bckdir = "%s/backup" % server.dir
server.ctl("zone-backup +keysonly +backupdir %s %s" % (bckdir, zones[0].name), wait=True)


server.ctl("-f zone-purge %s" % zones[0].name, wait=True)
check_key_count(server, kstore_dflt, 2)

server.ctl("-f zone-purge +kaspdb %s" % zones[0].name, wait=True)
check_key_count(server, kstore_dflt, 2)

#server.ctl("-f zone-purge +keys %s" % zones[0].name, wait=True)
check_key_count(server, kstore_dflt, 0)


server.ctl("zone-restore +keysonly +backupdir %s %s" % (bckdir, zones[1].name), wait=True)
check_key_count(server, kstore_dflt, 0)
check_key_count(server, kstore_pem, 4)



t.end()
