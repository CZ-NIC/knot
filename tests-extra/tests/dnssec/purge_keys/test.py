#!/usr/bin/env python3

"""
Test of DNSSEC keys purging.
"""

import os
import random
import shutil
from dnstest.utils import *
from dnstest.keys import Keymgr
from dnstest.keystore import KeystorePEM, KeystoreSoftHSM
from dnstest.test import Test

# Immediate test break is needed for debugging.
def issetbr(value, name):
    isset(value, name, fatal=True)

def comparebr(value, expected, name):
    compare(value, expected, name, fatal=True)

def zone_name_ksks_zsks(server, zone_name, keystore=None, trash=False):
    env = keystore.env() if keystore is not None else None
    command = "list" if not trash else "trash-list"
    _, keys, _ = Keymgr.run_check(server.confile, zone_name, command, env=env)

    ksks, zsks = [], []
    for key in keys.strip().splitlines():
        cols = key.split()
        if cols[1] == "ksk=yes":
            ksks.append(cols[0])
        if cols[2] == "zsk=yes":
            zsks.append(cols[0])

    return ksks, zsks

def zone_ksks_zsks(server, zone, keystore=None, trash=False):
    return zone_name_ksks_zsks(server, zone.name, keystore, trash)

def zone_keys(server, zone, keystore=None, trash=False):
    ksks, zsks = zone_ksks_zsks(server, zone, keystore, trash=trash)
    return ksks + zsks

def trash_keys(server, keystore=None):
    ksks, zsks = zone_name_ksks_zsks(server, "--", keystore, trash=True)
    return ksks + zsks

def check_key_count(keystore, expected):
    files = 0 if keystore is None else len(keystore.keys())
    comparebr(files, expected, "privkey count in %s" % keystore.id)

def check_keys_presence(keystore, keys, presence=True):
    if keystore is None:
        issetbr(keys is None, f"keystore None does not contain keys {keys}")
        return

    keystore_keys = keystore.keys()
    word = "" if presence else "not "
    for key_id in keys:
        issetbr((key_id in keystore_keys) is presence, f"key {key_id} {word}in keystore {keystore}")

def check_keys_in_keystore(keystore, total, present, absent):
    if keystore is None:
        issetbr(total == 0, f"number of keys {total} matches keystore None")
        issetbr(present is None, f"keystore None does not contain keys {present}")
        return

    list = keystore.keys()
    comparebr(len(list), total, "privkey count in %s" % keystore.id)
    for key_id in (present or []):
        issetbr(key_id in list, f"key {key_id} in keystore {keystore.id}")
    for key_id in (absent or []):
        issetbr(key_id not in list, f"key {key_id} not in keystore {keystore.id}")

def check_keys(keystore0, num0, keys0, not0, num1, keys1, not1, num2, keys2, not2):
    check_keys_in_keystore(keystore0,  num0, keys0, not0)
    check_keys_in_keystore(kstore_pem, num1, keys1, not1)
    # Avoid concurrent access to SoftHSM.
    server.ctl("zone-freeze %s %s" % (zones[6].name, zones[7].name), wait=True)
    check_keys_in_keystore(kstore_hsm, num2, keys2, not2)
    server.ctl("zone-thaw %s %s" % (zones[6].name, zones[7].name), wait=True)

def check_keys_in_kasp(server, zone, present, absent, keystore=None):
    list = zone_keys(server, zone, keystore)
    for key_id in (present or []):
        issetbr(key_id in list, f"key {key_id} of zone {zone.name} in KASP DB")
    for key_id in (absent or []):
        issetbr(key_id not in list, f"key {key_id} of zone {zone.name} not in KASP DB")

def check_kasp(keys0, not0, keys1, not1, keys2, not2, keys3, not3, keys4, not4,
               keys5, not5, keys6, not6, keys7, not7):
    check_keys_in_kasp(server, zones[0], keys0, not0)
    check_keys_in_kasp(server, zones[1], keys1, not1)
    check_keys_in_kasp(server, zones[2], keys2, not2)
    check_keys_in_kasp(server, zones[3], keys3, not3)
    check_keys_in_kasp(server, zones[4], keys4, not4)
    check_keys_in_kasp(server, zones[5], keys5, not5)
    # Avoid concurrent access to SoftHSM.
    server.ctl("zone-freeze %s %s" % (zones[6].name, zones[7].name), wait=True)
    check_keys_in_kasp(server, zones[6], keys6, not6, keystore=kstore_hsm)
    check_keys_in_kasp(server, zones[7], keys7, not7, keystore=kstore_hsm)
    server.ctl("zone-thaw %s %s" % (zones[6].name, zones[7].name), wait=True)

def check_trash_with_keystore(present, absent, keystore=None):
    trash = trash_keys(server, keystore)
    for key_id in (present or []):
        issetbr(key_id in trash, f"key {key_id} in trash (KASP DB)")
    for key_id in (absent or []):
        issetbr(key_id not in trash, f"key {key_id} not in trash (KASP DB)")

def check_trash(present, absent):
    check_trash_with_keystore(present, absent, keystore=kstore_hsm)

t = Test()

server = t.server("knot")
zones = t.zone_rnd(8, records=5)
t.link(zones, server)

kstore_def = KeystorePEM("default keystore", server_default=server)
kstore_pem = KeystorePEM("keys1")
kstore_hsm = KeystoreSoftHSM("keys2")
kstore_hsm.link(server)

# For every type of keystore, there are zones that have the "trash bin"
# enabled and that have it disabled. Otherwise they are equal.
# In kstore_pem, there are two pairs of zones, where each pair shares
# the KSK key.

server.dnssec(zones[0]).enable = True
server.dnssec(zones[0]).propagation_delay = 1
server.dnssec(zones[0]).trash_delay = 86400
# Default keystore for zones[0], not configured.

server.dnssec(zones[1]).enable = True
server.dnssec(zones[1]).propagation_delay = 1
server.dnssec(zones[1]).trash_delay = 0
# Default keystore for zones[1], not configured.

server.dnssec(zones[2]).enable = True
server.dnssec(zones[2]).propagation_delay = 1
server.dnssec(zones[2]).keystore = [ kstore_pem ]
server.dnssec(zones[2]).ksk_shared = True
server.dnssec(zones[2]).trash_delay = 86400

server.dnssec(zones[3]).enable = True
server.dnssec(zones[3]).shared_policy_with = zones[2].name

server.dnssec(zones[4]).enable = True
server.dnssec(zones[4]).propagation_delay = 1
server.dnssec(zones[4]).keystore = [ kstore_pem ]
server.dnssec(zones[4]).ksk_shared = True
server.dnssec(zones[4]).trash_delay = 0

server.dnssec(zones[5]).enable = True
server.dnssec(zones[5]).shared_policy_with = zones[4].name

server.dnssec(zones[6]).enable = True
server.dnssec(zones[6]).propagation_delay = 1
server.dnssec(zones[6]).keystore = [ kstore_hsm ]
server.dnssec(zones[6]).trash_delay = 86400

server.dnssec(zones[7]).enable = True
server.dnssec(zones[7]).propagation_delay = 1
server.dnssec(zones[7]).keystore = [ kstore_hsm ]
server.dnssec(zones[7]).trash_delay = 0

# Second server that shares keystores with the first server.
server2 = t.server("knot")
zones2 = t.zone_rnd(3)
t.link(zones2, server2)
kstore_hsm.link(server2)
kstore_def2 = None

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

# Create 'foreign' keys in shared keystores.
server2.start()
serial2 = server2.zones_wait(zones2)
keys2_zone0 = zone_keys(server2, zones2[0])
keys2_zone1 = zone_keys(server2, zones2[1])
server2.ctl("zone-freeze %s" % zones2[2].name, wait=True)
keys2_zone2 = zone_keys(server2, zones2[2], kstore_hsm)
server2.ctl("zone-thaw %s" % zones2[2].name, wait=True)
server2.stop()

s2keys = keys2_zone0 + keys2_zone1 + keys2_zone2

# Start the actual test. (server2 must stay stopped, SoftHSM doesn't like concurrent use.)
server.start()

serial = server.zones_wait(zones)
k0 = zone_keys(server, zones[0])
k1 = zone_keys(server, zones[1])
ksks2, zsks2 = zone_ksks_zsks(server, zones[2])
k2 = ksks2 + zsks2
k3 = zone_keys(server, zones[3])
ksks4, zsks4 = zone_ksks_zsks(server, zones[4])
k4 = ksks4 + zsks4
k5 = zone_keys(server, zones[5])
k6 = zone_keys(server, zones[6], kstore_hsm)
k7 = zone_keys(server, zones[7], kstore_hsm)

################################
# Purging keys of existing zones
################################

# When checking counts, don't forget to add number of keys from the other server.
check_kasp(k0, None, k1, None, k2, None, k3, None, k4, None, k5, None, k6, None, k7, None)
check_trash(None, k0 + k1 + k2 + k3 + k4 + k5 + k6 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 6 + 4, k2 + k3 + k4 + k5, None, 4 + 2, k6 + k7, None)
check_keys(kstore_def2, 0, None, None, 6 + 4, keys2_zone0 + keys2_zone1, None, 4 + 2, keys2_zone2, None)

bckdir = os.path.join(server.dir, "backup")
server.ctl("zone-backup +backupdir %s" % bckdir, wait=True)

# Test that keys aren't purged as a part of KASP DB purge.
server.ctl("-f zone-purge +kaspdb %s %s" % (zones[2].name, zones[4].name), wait=True)
check_kasp(k0, None, k1, None, k2, None, k3, None, k4, None, k5, None, k6, None, k7, None)
check_trash(None, k0 + k1 + k2 + k3 + k4 + k5 + k6 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 6 + 4, k2 + k3 + k4 + k5, None, 4 + 2, k6 + k7, None)
server.ctl("-f zone-purge %s %s" % (zones[6].name, zones[7].name), wait=True)
check_kasp(k0, None, k1, None, k2, None, k3, None, k4, None, k5, None, k6, None, k7, None)
check_trash(None, k0 + k1 + k2 + k3 + k4 + k5 + k6 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 6 + 4, k2 + k3 + k4 + k5, None, 4 + 2, k6 + k7, None)

# Test that keys aren't purged in default purge.
server.ctl("-f zone-purge %s %s" % (zones[2].name, zones[4].name), wait=True)
check_kasp(k0, None, k1, None, k2, None, k3, None, k4, None, k5, None, k6, None, k7, None)
check_trash(None, k0 + k1 + k2 + k3 + k4 + k5 + k6 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 6 + 4, k2 + k3 + k4 + k5, None, 4 + 2, k6 + k7, None)
server.ctl("-f zone-purge +kaspdb %s %s" % (zones[6].name, zones[7].name), wait=True)
check_kasp(k0, None, k1, None, k2, None, k3, None, k4, None, k5, None, k6, None, k7, None)
check_trash(None, k0 + k1 + k2 + k3 + k4 + k5 + k6 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 6 + 4, k2 + k3 + k4 + k5, None, 4 + 2, k6 + k7, None)

# Test that keys are purged when they should be, but a shared KSK key isn't affected.
server.ctl("-f zone-purge +keys %s %s" % (zones[2].name, zones[4].name), wait=True)
check_kasp(k0, None, k1, None, None, k2, k3, None, None, k4, k5, None, k6, None, k7, None)
check_trash(set(k2) - set(k3 + k5), k0 + k1 + k3 + k4 + k5 + k6 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 5 + 4, k2 + k3 + k5, set(k4) - set(k5), 4 + 2, k6 + k7, None)
server.ctl("-f zone-purge +keys %s %s" % (zones[6].name, zones[7].name), wait=True)
check_kasp(k0, None, k1, None, None, k2, k3, None, None, k4, k5, None, None, k6, None, k7)
check_trash(set(k2 + k6) - set(k3 + k5), k0 + k1 + k3 + k4 + k5 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 5 + 4, k2 + k3 + k5, set(k4) - set(k5), 2 + 2, k6, k7)

# Test that a shared KSK key is purged with the last user.
server.ctl("-f zone-purge +keys %s %s" % (zones[3].name, zones[5].name), wait=True)
check_kasp(k0, None, k1, None, None, k2, None, k3, None, k4, None, k5, None, k6, None, k7)
check_trash(k2 + k3 + k6, k0 + k1 + k4 + k5 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 3 + 4, k2 + k3, k4 + k5, 2 + 2, k6, k7)

# Test that non-defined (foreign) keys remain untouched.
check_keys(kstore_def2, 0, None, None, 3 + 4, keys2_zone0 + keys2_zone1, None, 2 + 2, keys2_zone2, None)

server.ctl("zone-restore +backupdir %s %s %s %s %s" % (bckdir, zones[2].name, zones[4].name,
                                                               zones[6].name, zones[7].name), wait=True)
# Keys in HSM cannot be backed up/restored, but their parameters are restored back to KASP DB.
check_kasp(k0, None, k1, None, k2, None, None, k3, k4, None, None, k5, k6, None, k7, None)
check_trash(set(k3) - set(k2), k0 + k1 + k2 + k4 + k5 + k6 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 5 + 4, k2 + k3 + k4, set(k5) - set(k4), 2 + 2, k6, k7)

# Test that a missing key doesn't matter in keys purging.
pem_file0 = os.path.join(kstore_pem.config(), k2[0]) + ".pem"
os.remove(pem_file0)
server.ctl("-f zone-purge +keys %s" % zones[2].name, wait=True)
check_kasp(k0, None, k1, None, None, k2, None, k3, k4, None, None, k5, k6, None, k7, None)
check_trash(k2 + k3, k0 + k1 + k4 + k5 + k6 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 4 + 4, set(k2 + k3 + k4) - {k2[0]}, set([*k5, k2[0]]) - set(k4),
           2 + 2, k6, k7)

pem_file0 = os.path.join(kstore_pem.config(), k4[0]) + ".pem"
os.remove(pem_file0)
server.ctl("-f zone-purge +keys %s" % zones[4].name, wait=True)
check_kasp(k0, None, k1, None, None, k2, None, k3, None, k4, None, k5, k6, None, k7, None)
check_trash(k2 + k3, k0 + k1 + k4 + k5 + k6 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 2 + 4, set(k2 + k3) - {k2[0]}, k4 + k5 + [k2[0]], 2 + 2, k6, k7)

# Test that a failed delete returns an error.
server.ctl("zone-restore +backupdir %s %s %s" % (bckdir, zones[2].name, zones[4].name), wait=True)
server.zone_wait(zones[4])
check_kasp(k0, None, k1, None, k2, None, None, k3, k4, None, None, k5, k6, None, k7, None)
check_trash(set(k3) - set(k2), k0 + k1 + k4 + k5 + k6 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 5 + 4, k2 + k3 + k4, set(k5) - set(k4), 2 + 2, k6, k7)
os.chmod(kstore_pem.config(), 0o550)  # Read-only PEM directory.
try:
    server.ctl("-f zone-purge +keys %s" % zones[4].name, wait=True)
    test_failed = True
    # The directory mode needs to be reset for the test maintenance.
except:
    test_failed = False
os.chmod(kstore_pem.config(), 0o750)  # Reset the PEM directory mode.
if test_failed:
    set_err("FAILED DELETE NOT REPORTED")

# Test that the key isn't purged from a keystore not defined for the zone.
check_kasp(k0, None, k1, None, k2, None, None, k3, k4, None, None, k5, k6, None, k7, None)
check_trash(set(k3) - set(k2), k0 + k1 + k4 + k5 + k6 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 5 + 4, k2 + k3 + k4, set(k5) - set(k4), 2 + 2, k6, k7)

# Make zones[2] and zones[4] use a different keystore while keeping zones[3] and zones[5] as is,
# but not using shared KSK's.
kstore_pem2 = KeystorePEM("keys3")
server.dnssec(zones[2]).keystore = [ kstore_pem2 ]
server.dnssec(zones[4]).keystore = [ kstore_pem2 ]

server.dnssec(zones[3]).shared_policy_with = None
server.dnssec(zones[3]).ksk_shared = False
server.dnssec(zones[3]).propagation_delay = 1
server.dnssec(zones[3]).keystore = [ kstore_pem ]
server.dnssec(zones[3]).trash_delay = 0

server.dnssec(zones[5]).shared_policy_with = None
server.dnssec(zones[5]).ksk_shared = False
server.dnssec(zones[5]).propagation_delay = 1
server.dnssec(zones[5]).keystore = [ kstore_pem ]
server.dnssec(zones[5]).trash_delay = 0
server.gen_confile()
server.reload()

# Wait for server startup, for zones[5] new ZKS key is created, which has been missing now.
server.zones_wait([zones[0], zones[2], zones[3], zones[4], zones[5]])
server.ctl("zone-restore +backupdir %s %s %s %s %s" % (bckdir, zones[2].name, zones[3].name,
                                                               zones[4].name, zones[5].name), wait=True)
server.zones_wait([zones[0], zones[2], zones[3], zones[4], zones[5]])

# There are two instances of the same KSK key now, which was shared originally.
# Keys of zones[2] remained as orphans in kstore_pem.
# In kstore_pem2, there are 2 generated and then deleted keys of zones[2] in kstore_pem2 (as trash now).
# For zones[5], there was also a recently generated and then deleted ZSK key (set not to be stored in
# the trash bin).
check_kasp(k0, None, k1, None, k2, None, k3, None, k4, None, k5, None, k6, None, k7, None)
check_trash(None, k0 + k1 + k2 + k3 + k4 + k5 + k6 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 6 + 4, k2 + k3 + k4 + k5, None, 2 + 2, k6, k7)
check_keys_in_keystore(kstore_pem2, 4, k2 + k4, None)

server.ctl("-f zone-purge +keys %s %s" % (zones[2].name, zones[4].name), wait=True)
# The KSK key of zones[2] and zones[4] are still in kstore_pem2, because the keys with same ID's are
# used by zone[3] and zones[5]. A different copies of the keys, though.
check_keys_in_keystore(kstore_pem2, 3, ksks2 + zsks2, zsks4)
# There are keys k3 and k5, orphaned keys k2 and k4 and keys from server2 in kstore_pem.
check_kasp(k0, None, k1, None, None, k2, k3, None, None, k4, k5, None, k6, None, k7, None)
check_trash(set(k2) - set(k3), k0 + k1 + k3 + k4 + k5 + k6 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 6 + 4, k2 + k3 + k4 + k5, None, 2 + 2, k6, k7)
check_keys(kstore_def2, 0, None, None, 6 + 4, keys2_zone0 + keys2_zone1, None, 2 + 2, keys2_zone2, None)

server.ctl("-f zone-purge +keys %s %s" % (zones[3].name, zones[5].name), wait=True)
# The shared KSK removed, the orphaned ZSK's from zones[2] and zones[4] still remain in kstore_pem.
check_kasp(k0, None, k1, None, None, k2, None, k3, None, k4, None, k5, k6, None, k7, None)
check_trash(set(k2) - set(k3), k0 + k1 + k3 + k4 + k5 + k6 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 2 + 4, zsks2, set(k3) - set(k2), 2 + 2, k6, k7)
check_keys(kstore_def2, 0, None, None, 2 + 4, keys2_zone0 + keys2_zone1, None, 2 + 2, keys2_zone2, None)
check_keys_in_keystore(kstore_pem2, 3, k2 + ksks4, zsks4)

# Restore and verify.
server.ctl("zone-restore +backupdir %s %s %s %s %s" % (bckdir, zones[2].name, zones[3].name,
                                                               zones[4].name, zones[5].name), wait=True)
server.zones_wait([zones[0], zones[2], zones[3], zones[4], zones[5]])
# The orphaned ZSK's from zones[2] and zones[4] still remain in kstore_pem.
check_kasp(k0, None, k1, None, k2, None, k3, None, k4, None, k5, None, k6, None, k7, None)
check_trash(None, k0 + k1 + k2 + k3 + k4 + k5 + k6 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 6 + 4, k2 + k3 + k4 + k5, None, 2 + 2, k6, k7)
check_keys(kstore_def2, 0, None, None, 6 + 4, keys2_zone0 + keys2_zone1, None, 2 + 2, keys2_zone2, None)
check_keys_in_keystore(kstore_pem2, 4, k2 + k4, None)

#######################
# Purging orphaned keys
#######################

# Revert to the original configuration and restore data (except keys in HSM).
server.dnssec(zones[2]).keystore = [ kstore_pem ]
server.dnssec(zones[3]).shared_policy_with = zones[2].name
server.dnssec(zones[4]).keystore = [ kstore_pem ]
server.dnssec(zones[5]).shared_policy_with = zones[4].name
server.gen_confile()
server.reload()
server.zones_wait([zones[0], zones[2], zones[3], zones[4], zones[5]])

server.ctl("zone-restore +backupdir %s %s %s %s %s" % (bckdir, zones[2].name, zones[3].name,
                                                               zones[4].name, zones[5].name), wait=True)
server.zones_wait([zones[0], zones[2], zones[3], zones[4], zones[5]])
check_kasp(k0, None, k1, None, k2, None, k3, None, k4, None, k5, None, k6, None, k7, None)
check_trash(None, k0 + k1 + k2 + k3 + k4 + k5 + k6 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 6 + 4, k2 + k3 + k4 + k5, None, 2 + 2, k6, k7)
check_keys(kstore_def2, 0, None, None, 6 + 4, keys2_zone0 + keys2_zone1, None, 2 + 2, keys2_zone2, None)
check_keys_in_keystore(kstore_pem2, 4, k2 + k4, None)

# Deconfigure zones[2], zones[3], and zones[4] -- create orphans.
confsock = server.ctl_sock_rnd()
server.ctl("conf-begin", custom_parm=confsock)
server.ctl("conf-unset zone[%s]" % zones[2].name, custom_parm=confsock)
server.ctl("conf-unset zone[%s]" % zones[3].name, custom_parm=confsock)
server.ctl("conf-unset zone[%s]" % zones[4].name, custom_parm=confsock)
server.ctl("conf-commit", custom_parm=confsock)
check_kasp(k0, None, k1, None, k2, None, k3, None, k4, None, k5, None, k6, None, k7, None)
check_trash(None, k0 + k1 + k2 + k3 + k4 + k5 + k6 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 6 + 4, k2 + k3 + k4 + k5, None, 2 + 2, k6, k7)

# Test that the orphan keys aren't purged in regular keys purge.
try:
    server.ctl("-f zone-purge +keys %s %s" % (zones[2].name, zones[4].name), wait=True)
    set_err("PURGING FROM UNCONFIGURED ZONE")
except:
    pass
check_kasp(k0, None, k1, None, k2, None, k3, None, k4, None, k5, None, k6, None, k7, None)
check_trash(None, k0 + k1 + k2 + k3 + k4 + k5 + k6 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 6 + 4, k2 + k3 + k4 + k5, None, 2 + 2, k6, k7)

# Test that keys aren't purged in KASP DB orphan purge.
server.ctl("-f zone-purge +orphan +kaspdb %s %s" % (zones[2].name, zones[4].name), wait=True)
check_kasp(k0, None, k1, None, k2, None, k3, None, k4, None, k5, None, k6, None, k7, None)
check_trash(None, k0 + k1 + k2 + k3 + k4 + k5 + k6 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 6 + 4, k2 + k3 + k4 + k5, None, 2 + 2, k6, k7)

# Test that keys aren't purged in default orphan purge.
server.ctl("-f zone-purge +orphan %s %s" % (zones[2].name, zones[4].name), wait=True)
check_kasp(k0, None, k1, None, k2, None, k3, None, k4, None, k5, None, k6, None, k7, None)
check_trash(None, k0 + k1 + k2 + k3 + k4 + k5 + k6 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 6 + 4, k2 + k3 + k4 + k5, None, 2 + 2, k6, k7)

# Test that orphaned keys are purged, but not orphans from other zones.
server.ctl("-f zone-purge +orphan +keys %s" % zones[4].name, wait=True)
check_kasp(k0, None, k1, None, k2, None, k3, None, None, k4, k5, None, k6, None, k7, None)
check_trash(set(k4) - set(k5), k0 + k1 + k2 + k3 + k5 + k6 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 6 + 4, k2 + k3 + k4 + k5, None, 2 + 2, k6, k7)

# Test that a missing key doesn't matter in orphan keys purging and that orphan keys are purged.
pem_file0 = os.path.join(kstore_pem.config(), zsks2[0]) + ".pem"
os.remove(pem_file0)
# Test that keys are purged in orphan keys purge.
server.ctl("-f zone-purge +orphan +keys --", wait=True)
check_kasp(k0, None, k1, None, None, k2, None, k3, None, k4, k5, None, k6, None, k7, None)
check_trash(set(k2 + k3 + k4) - set(k5), k0 + k1 + k5 + k6 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 5 + 4, set(k2 + k3 + k4 + k5) - set(zsks2), zsks2, 2 + 2, k6, k7)

##############################################
# Delete of keys and cleaning of the trash bin
##############################################

# Restore config, zones, and data (except keys in HSM).
server.ctl("-f zone-purge +keys %s %s" % (zones[6].name, zones[7].name), wait=True)
server.reload()
server.zones_wait([zones[0], zones[1], zones[2], zones[3], zones[4], zones[5]])
# Six additional keys are generated, three for zones[2] together with zones[3],
# one for each of zones[4], zones[6], and zones[7].
server.ctl("zone-restore +backupdir %s %s %s %s %s" % (bckdir, zones[2].name, zones[3].name,
                                                               zones[4].name, zones[5].name), wait=True)
# As a result of restore, three recently generated keys from zones[2] and zones[3] have been
# moved to trash, new key from zones[4] has been deleted.
server.ctl("zone-restore +zonefile +nokaspdb +backupdir %s %s %s" %
            (bckdir, zones[6].name, zones[7].name), wait=True)
server.zones_wait(zones)
k6old = k6
k7old = k7
k6 = zone_keys(server, zones[6], kstore_hsm) # New generated zones[6] keys in HSM.
k7 = zone_keys(server, zones[7], kstore_hsm) # New generated zones[7] keys in HSM.
check_kasp(k0, None, k1, None, k2, None, k3, None, k4, None, k5, None, k6, None, k7, None)
check_trash(None, k0 + k1 + k2 + k3 + k4 + k5 + k6 + k7 + s2keys)
check_keys(kstore_def, 4, k0 + k1, None, 9 + 4, k2 + k3 + k4 + k5, None, 6 + 2, k6 + k7 + k6old, k7old)
check_keys(kstore_def2, 0, None, None, 9 + 4, keys2_zone0 + keys2_zone1, None, 6 + 2, keys2_zone2, None)

keys_zone0_ksks_now, keys_zone0_zsks_now = zone_ksks_zsks(server, zones[0])
keys_zone1_ksks_now, keys_zone1_zsks_now = zone_ksks_zsks(server, zones[1])
keys_zone2_ksks_now, keys_zone2_zsks_now = zone_ksks_zsks(server, zones[2])
keys_zone3_ksks_now, keys_zone3_zsks_now = zone_ksks_zsks(server, zones[3])
keys_zone4_ksks_now, keys_zone4_zsks_now = zone_ksks_zsks(server, zones[4])
keys_zone5_ksks_now, keys_zone5_zsks_now = zone_ksks_zsks(server, zones[5])
keys_zone6_ksks_now, keys_zone6_zsks_now = zone_ksks_zsks(server, zones[6], kstore_hsm)
keys_zone7_ksks_now, keys_zone7_zsks_now = zone_ksks_zsks(server, zones[7], kstore_hsm)

# Test that deleted keys end in the trash bin according to respective zone's policy.
# Some keys are not being deleted (they are commented out) intentionally!
Keymgr.run_check(server.confile, zones[0].name, "delete", keys_zone0_ksks_now[0])
# Keymgr.run_check(server.confile, zones[0].name, "delete", keys_zone0_zsks_now[0])
Keymgr.run_check(server.confile, zones[1].name, "delete", keys_zone1_ksks_now[0])
Keymgr.run_check(server.confile, zones[1].name, "delete", keys_zone1_zsks_now[0])
Keymgr.run_check(server.confile, zones[2].name, "delete", keys_zone2_ksks_now[0])
Keymgr.run_check(server.confile, zones[2].name, "delete", keys_zone2_zsks_now[0])
# Keymgr.run_check(server.confile, zones[3].name, "delete", keys_zone3_ksks_now[0])
Keymgr.run_check(server.confile, zones[3].name, "delete", keys_zone3_zsks_now[0])
# Keymgr.run_check(server.confile, zones[4].name, "delete", keys_zone4_ksks_now[0])
Keymgr.run_check(server.confile, zones[4].name, "delete", keys_zone4_zsks_now[0])
Keymgr.run_check(server.confile, zones[5].name, "delete", keys_zone5_ksks_now[0])
# Keymgr.run_check(server.confile, zones[5].name, "delete", keys_zone5_zsks_now[0])
# Keymgr.run_check(server.confile, zones[6].name, "delete", keys_zone6_ksks_now[0], env=kstore_hsm.env())
Keymgr.run_check(server.confile, zones[6].name, "delete", keys_zone6_zsks_now[0], env=kstore_hsm.env())
Keymgr.run_check(server.confile, zones[7].name, "delete", keys_zone7_ksks_now[0], env=kstore_hsm.env())
Keymgr.run_check(server.confile, zones[7].name, "delete", keys_zone7_zsks_now[0], env=kstore_hsm.env())

# Verify that the keys are removed from the zones, but remain in keystores.
check_kasp(keys_zone0_zsks_now, keys_zone0_ksks_now, None, k1,
           None, k2, keys_zone3_ksks_now, keys_zone3_zsks_now,
           keys_zone4_ksks_now, keys_zone4_zsks_now, keys_zone5_zsks_now, keys_zone5_ksks_now,
           keys_zone6_ksks_now, keys_zone6_zsks_now, None, k7)
check_trash(keys_zone0_ksks_now + keys_zone2_zsks_now + keys_zone3_zsks_now + keys_zone6_zsks_now,
            keys_zone0_zsks_now + k1 + keys_zone2_ksks_now + keys_zone3_ksks_now + k4 + k5 + k7 + s2keys)
check_keys(kstore_def, 2, k0, k1,
                       8 + 4, k2 + k3 + k5, set(k4) - set(k5),
                       4 + 2, k6 + k6old, k7 + k7old)
check_keys(kstore_def2, 0, None, None, 8 + 4, keys2_zone0 + keys2_zone1, None, 4 + 2, keys2_zone2, None)

# Test removal of specified zone's keys from the trash.
Keymgr.run_check(server.confile, zones[2].name, "trash-discard", "--", env=kstore_hsm.env())
check_kasp(keys_zone0_zsks_now, keys_zone0_ksks_now, None, k1,
           None, k2, keys_zone3_ksks_now, keys_zone3_zsks_now,
           keys_zone4_ksks_now, keys_zone4_zsks_now, keys_zone5_zsks_now, keys_zone5_ksks_now,
           keys_zone6_ksks_now, keys_zone6_zsks_now, None, k7)
check_trash(keys_zone0_ksks_now + keys_zone3_zsks_now + keys_zone6_zsks_now,
            keys_zone0_zsks_now + k1 + keys_zone2_ksks_now + keys_zone3_ksks_now + k4 + k5 + k7 + s2keys)
check_keys(kstore_def, 2, k0, k1,
                       8 + 4, k2 + k3 + k5, set(k4) - set(k5),
                       4 + 2, k6 + k6old, k7 + k7old)
check_keys(kstore_def2, 0, None, None, 8 + 4, keys2_zone0 + keys2_zone1, None, 4 + 2, keys2_zone2, None)

# Test that "keymgr -- trash-discard --" cleans the trash bin (removes trash from keystores).
Keymgr.run_check(server.confile, "--", "trash-discard", "--", env=kstore_hsm.env())
# Six additional keys, already removed from the zones, have been discartded too.
check_kasp(keys_zone0_zsks_now, keys_zone0_ksks_now, None, k1,
           None, k2, keys_zone3_ksks_now, keys_zone3_zsks_now,
           keys_zone4_ksks_now, keys_zone4_zsks_now, keys_zone5_zsks_now, keys_zone5_ksks_now,
           keys_zone6_ksks_now, keys_zone6_zsks_now, None, k7)
check_trash(None,
            k0 + k1 + k2 + k3 + k4 + k5 + k6 + k7 + s2keys)
check_keys(kstore_def, 1, keys_zone0_zsks_now, keys_zone0_ksks_now + k1,
                       3 + 4, keys_zone3_ksks_now + k5,
                              keys_zone2_zsks_now + keys_zone3_zsks_now + keys_zone4_zsks_now,
                       1 + 2, keys_zone6_ksks_now, keys_zone6_zsks_now + k7 + k6old + k7old)
check_keys(kstore_def2, 0, None, None, 3 + 4, keys2_zone0 + keys2_zone1, None, 1 + 2, keys2_zone2, None)

t.end()
