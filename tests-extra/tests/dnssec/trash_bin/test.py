#!/usr/bin/env python3

"""
Test of DNSSEC "trash bin".
"""

from dnstest.keys import Keymgr
from dnstest.keystore import KeystoreDflt
from dnstest.test import Test
from dnstest.utils import *
import random
import time

def zone_ksks_zsks(server, zone, keystore=None, trash=False):
    env = keystore.env() if keystore is not None else None
    command = "list" if not trash else "trash-list"
    _, keys, _ = Keymgr.run_check(server.confile, zone.name, command, env=env)

    ksks, zsks = [], []
    for key in keys.strip().splitlines():
        cols = key.split()
        if cols[1] == "ksk=yes":
            ksks.append(cols[0])
        if cols[2] == "zsk=yes":
            zsks.append(cols[0])

    return ksks, zsks

def zone_keys(server, zone, keystore=None, trash=False):
    ksks, zsks = zone_ksks_zsks(server, zone, keystore, trash=trash)
    return ksks + zsks

def zone_trash_keys(server, zone, keystore=None):
    return zone_keys(server, zone, keystore, trash=True)

def check_key(server, zone, keystore, keyid, exists=True, trash=False):
    if exists and trash:
        set_err("CONFLICTING PARAMETERS")

    any = exists or trash
    isset((keyid in zone_keys(server, zone)) is exists,
          f"key {keyid} %sin KASP" % "" if exists else "not ")
    isset((keyid in zone_trash_keys(server, zone)) is trash,
          f"key {keyid} %sin trash bin" % "" if trash else "not ")
    isset((keyid in keystore.keys()) is any,
          f"key {keyid} %sin keystore" % "" if any else "not ")

t = Test()

master = t.server("knot")
zones = t.zone_rnd(1, records=5)
t.link(zones, master)

kstore = KeystoreDflt("default keystore", master)

# Fast (7 sec) automatic ZSK rollover.
master.dnssec(zones).enable = True
master.dnssec(zones).manual = False
master.dnssec(zones).dnskey_ttl = 1
master.dnssec(zones).zone_max_ttl = 2
master.dnssec(zones).propagation_delay = 1
master.dnssec(zones).zsk_lifetime = 5
master.dnssec(zones).trash_delay = 60

t.start()

zone = zones[0]
master.zone_wait(zone)
compare(zone_trash_keys(master, zone), [], "trash bin must be empty on test startup")

# Let the ZSK roll, fill the trash bin and collect all ID's of generated keys.
all_keys = set()
for i in range(22):
    all_keys.update(zone_keys(master, zone))
    t.sleep(2)

master.ctl("zone-freeze", wait=True)

all_keys.update(zone_keys(master, zone))
ksks, zsks = zone_ksks_zsks(master, zone) # We need list of KSK's.
keys = ksks + zsks
trash = zone_trash_keys(master, zone)

# Check that move to the trash bin instead of delete works.
compare(all_keys, set(keys + trash), "all keys metadata found (active and deleted)")
keystore_keys = kstore.keys()
compare(all_keys, set(keystore_keys), "all keys found in keystore (active and deleted)")

# Check that 'import-trash' works.
ksk = ksks[0]
check_key(master, zone, kstore, ksk, exists=True, trash=False)

Keymgr.run_check(master.confile, zone.name, "delete", ksk)
check_key(master, zone, kstore, ksk, exists=False, trash=True)

_, stdout, _ = Keymgr.run_check(master.confile, zone.name, "import-trash", ksk)
ksk_reimport = stdout.strip().splitlines()[0]
compare(ksk_reimport, ksk, f"deleted KSK key {ksk} reimported with the same Key ID")
check_key(master, zone, kstore, ksk, exists=True, trash=False)
cur_keys = zone_keys(master, zone)
cur_trash = zone_trash_keys(master, zone)
compare(set(keys), set(cur_keys), "keys did not change after delete/import-trash")
compare(set(trash), set(cur_trash), "trash did not change after delete/import-trash")
master.ctl("zone-sign %s" % zone.name, wait=True)
cur_ksks, cur_zsks = zone_ksks_zsks(master, zone)
compare(set(ksks), set(cur_ksks), "set of KSK's did not change after delete/import-trash/zone-sign")

# Check that 'trash-discard' works.
zsk_discarded = random.choice(trash)
Keymgr.run_check(master.confile, zone.name, "trash-discard", zsk_discarded)
check_key(master, zone, kstore, zsk_discarded, exists=False, trash=False)
cur_trash = list(set(trash) - {zsk_discarded})

# Check that 'trash-touch' works - step one.
zsk_touched = random.choice(cur_trash)
Keymgr.run_check(master.confile, zone.name, "trash-touch", zsk_touched)
check_key(master, zone, kstore, zsk_touched, exists=False, trash=True)
cur_trash_mod = list(set(cur_trash) - {zsk_touched})

master.ctl("zone-thaw", wait=True)

# The following checks require compile-time support in knotd binary.
# -DTRASH_GC_INTERVAL="30"
####gc_int = os.environ.get(TRASH_GC_INTERVAL)
####if gc_int is not None:
if False:
    # Let all known trash keys time out and wait for the next trash GC run.
    t.sleep(80)

    new_trash = zone_trash_keys(master, zone)
    new_keystore_keys = kstore.keys()

    # Check that the background garbage collector works.
    for key_id in cur_trash_mod:
        isset(key_id not in new_trash, f"key {key_id} removed from trash bin")
        isset(key_id not in new_keystore_keys, f"key {key_id} removed from trash bin keystore")

    # Check that 'trash-touch' works - step two.
    isset(zsk_touched in new_trash, f"touched key {key_id} kept in trash bin")
    isset(zsk_touched in new_keystore_keys, f"touched key {key_id} kept in trash bin keystore")

t.end()
