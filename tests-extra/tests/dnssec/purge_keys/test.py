#!/usr/bin/env python3

"""
Test of DNSSEC keys purging.
"""

import os
import random
import shutil
from dnstest.utils import *
from dnstest.keys import Keymgr
from dnstest.keystore import KeystoreDflt, KeystorePEM, KeystoreSoftHSM
from dnstest.test import Test

def zone_ksks_zsks(server, zone, keystore=None):
    env = keystore.env() if keystore is not None else None
    _, keys, _ = Keymgr.run_check(server.confile, zone.name, "list", env=env)

    ksks = []
    zsks = []
    for key in keys.strip().splitlines():
        cols = key.split()
        if cols[1] == "ksk=yes":
            ksks.append(cols[0])
        if cols[2] == "zsk=yes":
            zsks.append(cols[0])

    return ksks, zsks

def zone_keys(server, zone, keystore=None):
    ksks, zsks = zone_ksks_zsks(server, zone, keystore)
    return ksks + zsks

def check_key_count(keystore, expected):
    files = 0 if keystore is None else len(keystore.keys())
    compare(files, expected, "privkey count in %s" % keystore.id)

def check_keys_presence(keystore, keys, presence=True):
    if keystore is None:
        isset(keys is None, f"keystore None does not contain keys {keys}")
        return

    keystore_keys = keystore.keys()
    word = "" if presence else "not "
    for key_id in keys:
        isset((key_id in keystore_keys) is presence, f"key {key_id} {word}in keystore {keystore}")

def check_keys_in_keystore(keystore, total, present, absent):
    if keystore is None:
        isset(total == 0, f"number of keys {total} matches keystore None")
        isset(present is None, f"keystore None does not contain keys {present}")
        return

    list = keystore.keys()
    compare(len(list), total, "privkey count in %s" % keystore.id)
    for key_id in (present or []):
        isset(key_id in list, f"key {key_id} in keystore {keystore.id}")
    for key_id in (absent or []):
        isset(key_id not in list, f"key {key_id} not in keystore {keystore.id}")

def check_keys(keystore0, num0, keys0, not0, num1, keys1, not1, num2, keys2, not2):
    check_keys_in_keystore(keystore0,  num0, keys0, not0)
    check_keys_in_keystore(kstore_pem, num1, keys1, not1)
    server.ctl("zone-freeze %s" % zones[2].name, wait=True) # Avoid concurrent access to SoftHSM.
    check_keys_in_keystore(kstore_hsm, num2, keys2, not2)
    server.ctl("zone-thaw %s" % zones[2].name, wait=True)

t = Test()

server = t.server("knot")
zones = t.zone_rnd(4, records=5)
t.link(zones, server)

kstore_def = KeystoreDflt("default keystore", server)
kstore_pem = KeystorePEM("keys1")
kstore_hsm = KeystoreSoftHSM("keys2")
kstore_hsm.link(server)

server.dnssec(zones[0]).enable = True
server.dnssec(zones[0]).propagation_delay = 1
# Default keystore for zones[0], not configured.

server.dnssec(zones[1]).enable = True
server.dnssec(zones[1]).propagation_delay = 1
server.dnssec(zones[1]).keystore = [ kstore_pem ]
server.dnssec(zones[1]).ksk_shared = True
server.dnssec(zones[1]).trash_delay = 0

server.dnssec(zones[2]).enable = True
server.dnssec(zones[2]).propagation_delay = 1
server.dnssec(zones[2]).keystore = [ kstore_hsm ]
server.dnssec(zones[2]).trash_delay = 86400

server.dnssec(zones[3]).enable = True
server.dnssec(zones[3]).shared_policy_with = zones[1].name

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

# Start the actual test. (server2 must stay stopped, SoftHSM doesn't like concurrent use.)
server.start()

serial = server.zones_wait(zones)
keys_zone0 = zone_keys(server, zones[0])
keys_zone1_ksks, keys_zone1_zsks = zone_ksks_zsks(server, zones[1])
keys_zone1 = keys_zone1_ksks + keys_zone1_zsks
keys_zone2 = zone_keys(server, zones[2], kstore_hsm)
keys_zone3 = zone_keys(server, zones[3])

################################
# Purging keys of existing zones
################################

# When checking counts, don't forget to add number of keys from the other server.
check_keys(kstore_def, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 2 + 2, keys_zone2, None)
check_keys(kstore_def2, 0, None, None, 3 + 4, keys2_zone0 + keys2_zone1, None, 2 + 2, keys2_zone2, None)

bckdir = os.path.join(server.dir, "backup")
server.ctl("zone-backup +backupdir %s" % bckdir, wait=True)

# Test that keys aren't purged as a part of KASP DB purge.
server.ctl("-f zone-purge +kaspdb %s" % zones[1].name, wait=True)
check_keys(kstore_def, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 2 + 2, keys_zone2, None)
server.ctl("-f zone-purge %s" % zones[2].name, wait=True)
check_keys(kstore_def, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 2 + 2, keys_zone2, None)

# Test that keys aren't purged in default purge.
server.ctl("-f zone-purge %s" % zones[1].name, wait=True)
check_keys(kstore_def, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 2 + 2, keys_zone2, None)
server.ctl("-f zone-purge +kaspdb %s" % zones[2].name, wait=True)
check_keys(kstore_def, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 2 + 2, keys_zone2, None)

# Test that keys are purged when they should be, but a shared KSK key isn't affected.
server.ctl("-f zone-purge +keys %s" % zones[1].name, wait=True)
check_keys(kstore_def, 2, keys_zone0, None, 2 + 4, keys_zone3, set(keys_zone1) - set(keys_zone3), 2 + 2, keys_zone2, None)
server.ctl("-f zone-purge +keys %s" % zones[2].name, wait=True)
check_keys(kstore_def, 2, keys_zone0, None, 2 + 4, keys_zone3, set(keys_zone1) - set(keys_zone3), 0 + 2, None, keys_zone2)

# Test that a shared KSK key is purged with the last user.
server.ctl("-f zone-purge +keys %s" % zones[3].name, wait=True)
check_keys(kstore_def, 2, keys_zone0, None, 0 + 4, None, keys_zone1 + keys_zone3, 0 + 2, None, keys_zone2)

# Test that non-defined (foreign) keys remain untouched.
check_keys(kstore_def2, 0, None, None, 0 + 4, keys2_zone0 + keys2_zone1, None, 0 + 2, keys2_zone2, None)

server.ctl("zone-restore +backupdir %s %s %s" % (bckdir, zones[1].name, zones[2].name),
           wait=True)
# Keys in HSM cannot be backed up/restored, but their parameters are restored back to KASP DB.
check_keys(kstore_def, 2, keys_zone0, None, 2 + 4, keys_zone1, None, 0 + 2, 0, keys_zone2)

# Test that a missing key doesn't matter in keys purging.
pem_file0 = os.path.join(kstore_pem.config(), keys_zone1[0]) + ".pem"
os.remove(pem_file0)
server.ctl("-f zone-purge +keys %s" % zones[1].name, wait=True)
check_keys(kstore_def, 2, keys_zone0, None, 0 + 4, None, keys_zone1 + keys_zone3, 0 + 2, None, keys_zone2)

# Test that a failed delete returns an error.
server.ctl("zone-restore +backupdir %s %s" % (bckdir, zones[1].name), wait=True)
server.zone_wait(zones[1])
check_keys(kstore_def, 2, keys_zone0, None, 2 + 4, keys_zone1, set(keys_zone3) - set(keys_zone1), 0 + 2, None, keys_zone2)
os.chmod(kstore_pem.config(), 0o550)  # Read-only PEM directory.
try:
    server.ctl("-f zone-purge +keys %s" % zones[1].name, wait=True)
    test_failed = True
    # The directory mode needs to be reset for the test maintenance.
except:
    test_failed = False
os.chmod(kstore_pem.config(), 0o750)  # Reset the PEM directory mode.
if test_failed:
    set_err("FAILED DELETE NOT REPORTED")

# Test that the key isn't purged from a keystore not defined for the zone.
check_keys(kstore_def, 2, keys_zone0, None, 2 + 4, keys_zone1, set(keys_zone3) - set(keys_zone1), 0 + 2, None, keys_zone2)

kstore_pem2 = KeystorePEM("keys3")
server.dnssec(zones[1]).keystore = [ kstore_pem2 ]

server.dnssec(zones[3]).shared_policy_with = None
server.dnssec(zones[3]).ksk_shared = False
server.dnssec(zones[3]).propagation_delay = 1
server.dnssec(zones[3]).keystore = [ kstore_pem ]
server.dnssec(zones[3]).trash_delay = 0
server.gen_confile()
server.reload()

server.ctl("zone-restore +backupdir %s %s %s" % (bckdir, zones[1].name, zones[3].name), wait=True)
server.zones_wait([zones[0], zones[1], zones[3]])
# There are two instances of the same KSK key now, which was shared originally.
# Keys of zones[1] remained as orphans in kstore_pem.
check_keys(kstore_def, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 0 + 2, None, keys_zone2)
check_keys_in_keystore(kstore_pem2, 2, keys_zone1, None)
server.ctl("-f zone-purge +keys %s" % zones[1].name, wait=True)
# The KSK key of zones[1] is still in kstore_pem2, because the key with same ID is
# used by zone[3]. A different copy of the key, though.
check_keys_in_keystore(kstore_pem2, 1, keys_zone1_ksks, keys_zone1_zsks)
# There are keys_zone3, orphaned keys_zone1 and keys from server2 in kstore_pem.
check_keys(kstore_def, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 0 + 2, None, keys_zone2)
check_keys(kstore_def2, 0, None, None, 3 + 4, keys2_zone0 + keys2_zone1, None, 0 + 2, keys2_zone2, None)

server.ctl("-f zone-purge +keys %s" % zones[3].name, wait=True)
# The shared KSK removed, the orphaned ZSK from zones[1] still remains in kstore_pem.
check_keys(kstore_def, 2, keys_zone0, None, 1 + 4, keys_zone1_zsks, set(keys_zone3) - set(keys_zone1), 0 + 2, None, keys_zone2)
check_keys(kstore_def2, 0, None, None, 1 + 4, keys2_zone0 + keys2_zone1, None, 0 + 2, keys2_zone2, None)
check_keys_in_keystore(kstore_pem2, 1, keys_zone1_ksks, keys_zone1_zsks)

server.ctl("zone-restore +backupdir %s %s %s" % (bckdir, zones[1].name, zones[3].name),
           wait=True)
server.zones_wait([zones[0], zones[1], zones[3]])
# The orphaned ZSK from zones[1] still remains in kstore_pem.
check_keys(kstore_def, 2, keys_zone0, None, 3 + 4, keys_zone3 + keys_zone1_zsks, None, 0 + 2, None, keys_zone2)
check_keys_in_keystore(kstore_pem2, 2, keys_zone1, None)

#######################
# Purging orphaned keys
#######################

# Revert to the original configuration and restore data (except keys in HSM).
server.dnssec(zones[1]).keystore = [ kstore_pem ]
server.dnssec(zones[3]).shared_policy_with = zones[1].name
server.gen_confile()
server.reload()
server.zones_wait([zones[0], zones[1], zones[3]])

server.ctl("zone-restore +backupdir %s %s %s" % (bckdir, zones[1].name, zones[3].name), wait=True)
server.zones_wait([zones[0], zones[1], zones[3]])
check_keys(kstore_def, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 0 + 2, None, keys_zone2)
check_keys_in_keystore(kstore_pem2, 2, keys_zone1, None)

# Deconfigure zones[1] and zones[3] -- create orphans.
confsock = server.ctl_sock_rnd()
server.ctl("conf-begin", custom_parm=confsock)
server.ctl("conf-unset zone[%s]" % zones[1].name, custom_parm=confsock)
server.ctl("conf-unset zone[%s]" % zones[3].name, custom_parm=confsock)
server.ctl("conf-commit", custom_parm=confsock)
check_keys(kstore_def, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 0 + 2, None, keys_zone2)

# Test that the orphan keys aren't purged in regular keys purge.
try:
    server.ctl("-f zone-purge +keys %s" % zones[1].name, wait=True)
    set_err("PURGING FROM UNCONFIGURED ZONE")
except:
    pass
check_keys(kstore_def, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 0 + 2, None, keys_zone2)

# Test that keys aren't purged in KASP DB orphan purge.
server.ctl("-f zone-purge +orphan +kaspdb %s" % zones[1].name, wait=True)
check_keys(kstore_def, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 0 + 2, None, keys_zone2)

# Test that keys aren't purged in default orphan purge.
server.ctl("-f zone-purge +orphan %s" % zones[1].name, wait=True)
check_keys(kstore_def, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 0 + 2, None, keys_zone2)

# Test that a failed orphan delete returns an error.
os.chmod(kstore_pem.config(), 0o550)  # Read-only PEM directory.
try:
    server.ctl("-f zone-purge +orphan +keys %s" % zones[1].name, wait=True)
    test_failed = True
    # The directory mode needs to be reset for the test maintenance.
except:
    test_failed = False
os.chmod(kstore_pem.config(), 0o750)  # Reset the PEM directory mode.
if test_failed:
    set_err("FAILED ORPHAN DELETE NOT REPORTED")
check_keys(kstore_def, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 0 + 2, None, keys_zone2)
# Check what was removed from KASP DB, it depends on records order in KASP DB.
# The shared KSK is orphaned in both zones!
keys_zone1_ksks_now, keys_zone1_zsks_now = zone_ksks_zsks(server, zones[1])
zsk_deleted_first = (keys_zone1_ksks == keys_zone1_ksks_now)

# Test that orphaned keys are purged, but not orphans from other zones.
server.ctl("-f zone-purge +orphan +keys %s" % zones[3].name, wait=True)
if zsk_deleted_first:
    # keys_zone1_zsks were deleted first from KASP DB, keys_zone1_ksks were therefore kept.
    check_keys(kstore_def, 2, keys_zone0, None, 2 + 4, keys_zone1, set(keys_zone3) - set(keys_zone1), 0 + 2, None, keys_zone2)
else:
    # keys_zone1_ksks were deleted first from KASP DB.
    check_keys(kstore_def, 2, keys_zone0, None, 1 + 4, set(keys_zone1) - set(keys_zone3), keys_zone3, 0 + 2, None, keys_zone2)

# Test that a missing key doesn't matter in orphan keys purging and that orphan keys are purged.
pem_file0 = os.path.join(kstore_pem.config(), keys_zone1_zsks[0]) + ".pem"
os.remove(pem_file0)
# Test that keys are purged in orphan keys purge.
server.ctl("-f zone-purge +orphan +keys --", wait=True)
check_keys(kstore_def, 2, keys_zone0, None, 0 + 4, None, keys_zone1 + keys_zone3, 0 + 2, None, keys_zone2)

####################
# Use of a trash bin
####################

# Restore config, zones and data (except keys in HSM).
server.ctl("-f zone-purge +keys %s" % zones[2].name, wait=True)
server.reload()
server.zones_wait([zones[0], zones[1], zones[3]])
server.ctl("zone-restore +backupdir %s %s %s" % (bckdir, zones[1].name, zones[3].name), wait=True)
server.ctl("zone-restore +zonefile +nokaspdb +backupdir %s %s" % (bckdir, zones[2].name), wait=True)
server.zones_wait(zones)
keys_zone2 = zone_keys(server, zones[2], kstore_hsm) # New generated zones[2] keys in HSM.
check_keys(kstore_def, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 2 + 2, keys_zone2, None)
check_keys(kstore_def2, 0, None, None, 3 + 4, keys2_zone0 + keys2_zone1, None, 2 + 2, keys2_zone2, None)

# Activate trash bin for zones zones[1] and zones[3].
server.dnssec(zones[1]).trash_delay = 86400
server.dnssec(zones[3]).trash_delay = 86400
server.gen_confile() # Needed by keymgr.
# Skipping server reload to avoid delays because of Valgrind (don't slow down the test).
server.ctl("conf-begin", custom_parm=confsock)
server.ctl("conf-set policy[%s].trash-delay 86400" % zones[1].name, custom_parm=confsock)
server.ctl("conf-set policy[%s].trash-delay 86400" % zones[3].name, custom_parm=confsock)
server.ctl("conf-commit", custom_parm=confsock)
server.ctl("zone-reload %s %s" % (zones[1].name, zones[3].name), custom_parm=confsock)
server.zones_wait(zones)
server.ctl("zone-freeze", wait=True)
check_keys(kstore_def, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 2 + 2, keys_zone2, None)

# Test that deleted keys end in the trash bin (i.e. they remain in keystores).
keys_zone0_ksks_now, keys_zone0_zsks_now = zone_ksks_zsks(server, zones[0])
keys_zone1_ksks_now, keys_zone1_zsks_now = zone_ksks_zsks(server, zones[1])
keys_zone2_ksks_now, keys_zone2_zsks_now = zone_ksks_zsks(server, zones[2], kstore_hsm)
keys_zone3_ksks_now, keys_zone3_zsks_now = zone_ksks_zsks(server, zones[3])
Keymgr.run_check(server.confile, zones[0].name, "delete", keys_zone0_ksks_now[0])
Keymgr.run_check(server.confile, zones[0].name, "delete", keys_zone0_zsks_now[0])
Keymgr.run_check(server.confile, zones[1].name, "delete", keys_zone1_ksks_now[0])
# Keep this: Keymgr.run_check(server.confile, zones[1].name, "delete", keys_zone1_zsks_now[0])
Keymgr.run_check(server.confile, zones[2].name, "delete", keys_zone2_ksks_now[0], env=kstore_hsm.env())
# Kepp this: Keymgr.run_check(server.confile, zones[2].name, "delete", keys_zone2_zsks_now[0], env=kstore_hsm.env())
Keymgr.run_check(server.confile, zones[3].name, "delete", keys_zone3_ksks_now[0])
Keymgr.run_check(server.confile, zones[3].name, "delete", keys_zone3_zsks_now[0])
# Verify that the keys are removed from the zones, but remain in keystores.
compare(zone_ksks_zsks(server, zones[0]), ([], []), "deleted keys from zone %s" % zones[0].name)
compare(zone_ksks_zsks(server, zones[1]), ([], keys_zone1_zsks_now), "deleted keys from zone %s" % zones[1].name)
compare(zone_ksks_zsks(server, zones[2], kstore_hsm), ([], keys_zone2_zsks_now), "deleted keys from zone %s" % zones[2].name)
compare(zone_ksks_zsks(server, zones[3]), ([], []), "deleted keys from zone %s" % zones[3].name)
check_keys(kstore_def, 2, keys_zone0, None, 3 + 4, keys_zone1 + keys_zone3, None, 2 + 2, keys_zone2, None)

# Test that "zone-purge -f +orphan +keys --" cleans the trash bin (removes trash from keystores).
server.ctl("-f zone-purge +orphan +keys --", wait=True)
check_keys(kstore_def, 0, None, keys_zone0, 1 + 4, keys_zone1_zsks_now, set(keys_zone1 + keys_zone3) - set(keys_zone1_zsks_now),
                                            1 + 2, keys_zone2_zsks_now, set(keys_zone2) - set (keys_zone2_zsks_now))
check_keys(kstore_def2, 0, None, None, 1 + 4, keys2_zone0 + keys2_zone1, None, 1 + 2, keys2_zone2, None)

t.end()
