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

def zone_keys_keystore(server, zone, keystore=None):
    env = keystore.env() if keystore is not None else None

    _, keys, _ = Keymgr.run_check(server.confile, zone.name, "list", env=env)
    return [key.split()[0] for key in keys.strip().splitlines()]

def check_keys_presence(keystore, keys, presence=True):
    word = "not " if presence else ""
    for key_id in keys:
        isset(keystore.has_key(key_id) is presence, f"key {key_id} {word}in keystore {keystore}")

t = Test()

server = t.server("knot")
zones = t.zone_rnd(3)
t.link(zones, server)

kstore_dflt = None  # Default keystore.
kstore_pem = KeystorePEM("keys1")
kstore_hsm = KeystoreSoftHSM("keys2")
kstore_hsm.link(server)

server.dnssec(zones[0]).enable = True
server.dnssec(zones[0]).propagation_delay = 1
# Default keystore for zones[0].

server.dnssec(zones[1]).enable = True
server.dnssec(zones[1]).propagation_delay = 1
server.dnssec(zones[1]).keystore = [ kstore_pem ]

server.dnssec(zones[2]).enable = True
server.dnssec(zones[2]).propagation_delay = 1
server.dnssec(zones[2]).keystore = [ kstore_hsm ]

t.start()
serial = server.zones_wait(zones)

#check_key_count(server, kstore_dflt, 2)
check_key_count(server, kstore_pem, 2)
#check_key_count(server, kstore_hsm, 2)

keys_zone0 = zone_keys_keystore(server, zones[0])
keys_zone1 = zone_keys_keystore(server, zones[1])
keys_zone2 = zone_keys_keystore(server, zones[2], kstore_hsm)

bckdir = "%s/backup" % server.dir
server.ctl("zone-backup +keysonly +backupdir %s %s %s" % (bckdir, zones[1].name, zones[2].name),
           wait=True)

# Test that the keys aren't purged in default purge.
server.ctl("-f zone-purge %s" % zones[1].name, wait=True)
check_key_count(server, kstore_pem, 2)
#check_key_count(server, kstore_hsm, 2)
check_keys_presence(kstore_pem, keys_zone1)
check_keys_presence(kstore_hsm, keys_zone2)
server.ctl("-f zone-purge %s" % zones[2].name, wait=True)
check_key_count(server, kstore_pem, 2)
#check_key_count(server, kstore_hsm, 2)
check_keys_presence(kstore_pem, keys_zone1)
check_keys_presence(kstore_hsm, keys_zone2)


# Test that the keys aren't purged as a part of KASP DB purge.
server.ctl("-f zone-purge +kaspdb %s" % zones[1].name, wait=True)
check_key_count(server, kstore_pem, 2)
#check_key_count(server, kstore_hsm, 2)
check_keys_presence(kstore_pem, keys_zone1)
check_keys_presence(kstore_hsm, keys_zone2)
server.ctl("-f zone-purge +kaspdb %s" % zones[2].name, wait=True)
check_key_count(server, kstore_pem, 2)
#check_key_count(server, kstore_hsm, 2)
check_keys_presence(kstore_pem, keys_zone1)
check_keys_presence(kstore_hsm, keys_zone2)


# Test that the keys are purged when they should be.
server.ctl("-f zone-purge +keys %s" % zones[1].name, wait=True)
check_key_count(server, kstore_pem, 0)
#check_key_count(server, kstore_hsm, 0)
check_keys_presence(kstore_pem, keys_zone1, False)
check_keys_presence(kstore_hsm, keys_zone2)
server.ctl("-f zone-purge +keys %s" % zones[2].name, wait=True)
check_key_count(server, kstore_pem, 0)
#check_key_count(server, kstore_hsm, 0)
check_keys_presence(kstore_pem, keys_zone1, False)
check_keys_presence(kstore_hsm, keys_zone2, False)


server.ctl("zone-restore +keysonly +backupdir %s" % bckdir, wait=True)
#check_key_count(server, kstore_dflt, 0)
#check_key_count(server, kstore_pem, 4)


t.end()
