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
    word = "" if presence else "not "
    for key_id in keys:
        isset(keystore.has_key(key_id) is presence, f"key {key_id} {word}in keystore {keystore}")

def check_counts(server, expect0, keys0, not0, expect1, keys1, not1, expect2, keys2, not2):
    check_key_count(server, kstore_def, expect0)
    check_key_count(server, kstore_pem, expect1)
    # check_key_count(server, kstore_hsm, expect2)

    #if keys0 is not None:
    #    check_keys_presence(kstore_def, keys0)
    if keys1 is not None:
        check_keys_presence(kstore_pem, keys1)
    if keys2 is not None:
        check_keys_presence(kstore_hsm, keys2)

    #if not0 is not None:
    #    check_keys_presence(kstore_def, not0, False)
    if not1 is not None:
        check_keys_presence(kstore_pem, not1, False)
    if not0 is not None:
        check_keys_presence(kstore_hsm, not2, False)

t = Test()

server = t.server("knot")
zones = t.zone_rnd(4)
t.link(zones, server)

kstore_def = None  # Default keystore.
kstore_pem = KeystorePEM("keys1")
kstore_hsm = KeystoreSoftHSM("keys2")
kstore_hsm.link(server)

server.dnssec(zones[0]).enable = True
server.dnssec(zones[0]).propagation_delay = 1
# Default keystore for zones[0].

server.dnssec(zones[1]).enable = True
server.dnssec(zones[1]).propagation_delay = 1
server.dnssec(zones[1]).keystore = [ kstore_pem ]
server.dnssec(zones[1]).ksk_shared = True
server.dnssec(zones[1]).trash_delay = 0

server.dnssec(zones[2]).enable = True
server.dnssec(zones[2]).propagation_delay = 1
server.dnssec(zones[2]).keystore = [ kstore_hsm ]

server.dnssec(zones[3]).enable = True
server.dnssec(zones[3]).shared_policy_with = zones[1].name
#server.dnssec(zones[3]).propagation_delay = 1
#server.dnssec(zones[3]).keystore = [ kstore_pem ]
#server.dnssec(zones[3]).ksk_shared = True
#server.dnssec(zones[3]).trash_delay = 0

server2 = t.server("knot")
zones2 = t.zone_rnd(3)
t.link(zones2, server2)
kstore_hsm.link(server2)

server2.dnssec(zones2[0]).enable = True
server2.dnssec(zones2[0]).propagation_delay = 1
server2.dnssec(zones2[0]).keystore = [ kstore_pem ]

server2.dnssec(zones2[1]).enable = True
server2.dnssec(zones2[1]).propagation_delay = 1
server2.dnssec(zones2[1]).keystore = [ kstore_pem ]

server2.dnssec(zones2[2]).enable = True
server2.dnssec(zones2[2]).propagation_delay = 1
server2.dnssec(zones2[2]).keystore = [ kstore_hsm ]

t.generate_conf()

# Create 'foreign' keys in keystores.
server2.start()
serial2 = server2.zones_wait(zones2)
keys2_zone0 = zone_keys_keystore(server2, zones2[0])
keys2_zone1 = zone_keys_keystore(server2, zones2[1])
keys2_zone2 = zone_keys_keystore(server2, zones2[2], kstore_hsm)
server2.stop()

# Start the actual test. (server2 must stay stopped, SoftHSM doesn't support parallel use.)
server.start()

serial = server.zones_wait(zones)
keys_zone0 = zone_keys_keystore(server, zones[0])
keys_zone1 = zone_keys_keystore(server, zones[1])
keys_zone2 = zone_keys_keystore(server, zones[2], kstore_hsm)
keys_zone3 = zone_keys_keystore(server, zones[3])

check_counts(server, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 2 + 2, keys_zone2, None)

check_counts(server, 2 + 0, keys_zone0,              None,
                     3 + 4, keys_zone1 + keys_zone3, None,
                     2 + 2, keys_zone2,              None)

check_counts(server2, 0, None, None, 3 + 4, keys2_zone0 + keys2_zone1, None, 2 + 2, keys2_zone2, None)

bckdir = "%s/backup" % server.dir
server.ctl("zone-backup +backupdir %s" % bckdir, wait=True)

# Test that the keys aren't purged in default purge.
server.ctl("-f zone-purge %s" % zones[1].name, wait=True)
check_counts(server, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 2 + 2, keys_zone2, None)
server.ctl("-f zone-purge %s" % zones[2].name, wait=True)
check_counts(server, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 2 + 2, keys_zone2, None)

# Test that the keys aren't purged as a part of KASP DB purge.
server.ctl("-f zone-purge +kaspdb %s" % zones[1].name, wait=True)
check_counts(server, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 2 + 2, keys_zone2, None)
server.ctl("-f zone-purge +kaspdb %s" % zones[2].name, wait=True)
check_counts(server, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 2 + 2, keys_zone2, None)

# Test that the keys are purged when they should be, but not a shared KSK key.
server.ctl("-f zone-purge +keys %s" % zones[1].name, wait=True)
check_counts(server, 2, keys_zone0, None, 2 + 4, keys_zone3, set(keys_zone1) - set(keys_zone3), 2 + 2, keys_zone2, None)
server.ctl("-f zone-purge +keys %s" % zones[2].name, wait=True)
check_counts(server, 2, keys_zone0, None, 2 + 4, keys_zone3, list(set(keys_zone1) - set(keys_zone3)), 0 + 2, None, keys_zone2)

# Test that a shared KSK key is purged with the last user.
server.ctl("-f zone-purge +keys %s" % zones[3].name, wait=True)
check_counts(server, 2, keys_zone0, None, 0 + 4, None, keys_zone1 + keys_zone3, 0 + 2, None, keys_zone2)

# Test that non-defined (foreign) keys remain untouched.
check_counts(server2, 0, None, None, 0 + 4, keys2_zone0 + keys2_zone1, None, 0 + 2, None, None)

server.ctl("zone-restore +backupdir %s %s %s" % (bckdir, zones[1].name, zones[2].name),
           wait=True)
# Keys in HSM cannot be backed up/restored.
check_counts(server, 2, keys_zone0, None, 2 + 4, keys_zone1, None, 0 + 2, None, keys_zone2)

# Test that a missing key doesn't matter in keys purging.
pem_file0 = os.path.join(kstore_pem.config(), keys_zone1[0]) + ".pem"
os.remove(pem_file0)
server.ctl("-f zone-purge +keys %s" % zones[1].name, wait=True)
check_counts(server, 2, keys_zone0, None, 0 + 4, None, keys_zone1 + keys_zone3, 0 + 2, None, keys_zone2)

# Test that a failed delete returns an error.
server.ctl("zone-restore +backupdir %s %s" % (bckdir, zones[1].name), wait=True)
server.zone_wait(zones[1])
check_counts(server, 2, keys_zone0, None, 2 + 4, keys_zone1, set(keys_zone3) - set(keys_zone1), 0 + 2, None, keys_zone2)
os.chmod(kstore_pem.config(), 0o550)  # Read-only PEM directory.
try:
    server.ctl("-f zone-purge +keys %s" % zones[1].name, wait=True)
    test_failed = True
    # The directory mode needs to be reset for the directory maintenance.
except:
    test_failed = False
os.chmod(kstore_pem.config(), 0o750)  # Reset the PEM directory mode.
if test_failed:
    set_err("FAILED DELETE NOT REPORTED")

# Test that the key isn't purged from a keystore not defined for the zone.
check_counts(server, 2, keys_zone0, None, 2 + 4, keys_zone1, set(keys_zone3) - set(keys_zone1), 0 + 2, None, keys_zone2)
kstore_pem2 = KeystorePEM("keys12")

server.dnssec(zones[3]).ksk_shared = False
server.dnssec(zones[3]).propagation_delay = 1
server.dnssec(zones[3]).keystore = [ kstore_pem ]
server.dnssec(zones[3]).trash_delay = 0
server.dnssec(zones[3]).shared_policy_with = None

server.dnssec(zones[1]).keystore = [ kstore_pem2 ]
server.gen_confile()
server.reload()
server.ctl("zone-restore +backupdir %s %s %s" % (bckdir, zones[1].name, zones[3].name), wait=True)
server.zones_wait([zones[0], zones[1], zones[3]])
# There are two instances of the same KSK key now, which was shared originally.
# Keys of zone[1] remained as orphans in kstore_pem.
check_counts(server, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 0 + 2, None, keys_zone2)
check_key_count(server, kstore_pem2, 2)
check_keys_presence(kstore_pem2, keys_zone1)
server.ctl("-f zone-purge +keys %s" % zones[1].name, wait=True)
# The KSK key of zone[1] is still in kstore_pem2, because the key with same ID is
# used by zone[3]. A different copy of the key, though.
check_key_count(server, kstore_pem2, 1)
# There are keys_zone3, orphaned keys_zone1 and keys from server2 in kstore_pem2.
#check_keys_presence(kstore_pem2, keys_zone1, False)
check_counts(server, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 0 + 2, None, keys_zone2)
check_counts(server2, 0, None, None, 3 + 4, keys2_zone0 + keys2_zone1, None, 0 + 2, None, None)

server.ctl("-f zone-purge +keys %s" % zones[3].name, wait=True)
# The shared KSK removed, the orphaned ZSK from zones[1] still remains in kstore_pem.
check_key_count(server, kstore_pem2, 1)
check_counts(server, 2, keys_zone0, None, 1 + 4, None, set(keys_zone3) - set(keys_zone1), 0 + 2, None, keys_zone2)
check_counts(server2, 0, None, None, 1 + 4, keys2_zone0 + keys2_zone1, None, 0 + 2, None, None)

server.ctl("zone-restore +backupdir %s %s %s" % (bckdir, zones[1].name, zones[3].name),
           wait=True)
server.zones_wait([zones[0], zones[1], zones[3]])
# The orphaned ZSK from zones[1] still remains in kstore_pem.
check_counts(server, 2, keys_zone0, None, 3 + 4, keys_zone3, None, 0 + 2, None, keys_zone2)



# Revert the original configuration and resore data (except keys in HSM).
server.dnssec(zones[1]).keystore = [ kstore_pem ]
server.dnssec(zones[3]).shared_policy_with = zones[1].name
server.gen_confile()
server.reload()
server.zones_wait([zones[0], zones[1], zones[3]])

server.ctl("zone-restore +backupdir %s %s %s" % (bckdir, zones[1].name, zones[3].name), wait=True)
server.zones_wait([zones[0], zones[1], zones[3]])
check_counts(server, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 0 + 2, None, keys_zone2)

# Deconfigure zones[1] -- create orphans.
confsock = server.ctl_sock_rnd()
server.ctl("conf-begin", custom_parm=confsock)
server.ctl("conf-unset zone[%s]" % zones[1].name, custom_parm=confsock)
server.ctl("conf-commit", custom_parm=confsock)
check_counts(server, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 0 + 2, None, keys_zone2)

# Test that the orphan keys aren't purged in regular keys purge.
try:
    server.ctl("-f zone-purge +keys %s" % zones[1].name, wait=True)
    set_err("PURGING FROM UNCONFIGURED ZONE")
except:
    pass
check_counts(server, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 0 + 2, None, keys_zone2)

# Test that the keys aren't purged in KASP DB orphan purge.
server.ctl("-f zone-purge +orphan %s" % zones[1].name, wait=True)
check_counts(server, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 0 + 2, None, keys_zone2)

# Test that the keys aren't purged in default orphan purge.
server.ctl("-f zone-purge +orphan %s" % zones[1].name, wait=True)
check_counts(server, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 0 + 2, None, keys_zone2)

# Test that the keys are purged in orphan keys purge.
server.ctl("-f zone-purge +orphan +keys %s" % zones[1].name, wait=True)
check_counts(server, 2, keys_zone0, None, 2 + 4, keys_zone3, set(keys_zone1) - set(keys_zone3), 0 + 2, None, keys_zone2)

t.end()
