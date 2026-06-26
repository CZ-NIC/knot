#!/usr/bin/env python3

"""
Test of DNSSEC "trash bin".
"""

from dnstest.keys import Keymgr
from dnstest.keystore import KeystorePEM
from dnstest.test import Test
from dnstest.utils import *
from subprocess import run, PIPE
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

# Immediate test break is needed for debugging.
def issetbr(value, name):
    isset(value, name, fatal=True)

def comparebr(value, expected, name):
    compare(value, expected, name, fatal=True)

def check_key(server, zone, keystore, keyid, exists=True, trash=False):
    if exists and trash:
        raise Failed("Conflicting parameters")

    any = exists or trash
    issetbr((keyid in zone_keys(server, zone)) is exists,
            f"key {keyid} %sin KASP" % "" if exists else "not ")
    issetbr((keyid in zone_trash_keys(server, zone)) is trash,
            f"key {keyid} %sin trash bin" % "" if trash else "not ")
    issetbr((keyid in keystore.keys()) is any,
            f"key {keyid} %sin keystore" % "" if any else "not ")

def check_gc_interval(server):
    res = run([server.daemon_bin, '-VV'], stdout=PIPE)
    for line in res.stdout.decode('ascii').split("\n"):
        if "    Configure: " in line:
            return True if "'--with-gc-interval=30'" in line else False
    raise Failed("Malformed configuration summary")

t = Test()

master = t.server("knot")
zones = t.zone_rnd(1, records=5)
t.link(zones, master)

kstore = KeystorePEM("default keystore", server_default=master)

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
comparebr(zone_trash_keys(master, zone), [], "trash bin must be empty on test startup")

# Let the ZSK roll, fill the trash bin and collect all ID's of generated keys.
# The background GC periodic intervals start with the first ZSK rollover, not earlier!
all_keys = set()
for i in range(25):
    all_keys.update(zone_keys(master, zone))
    t.sleep(2)

master.ctl("zone-freeze", wait=True)

all_keys.update(zone_keys(master, zone))
ksks, zsks = zone_ksks_zsks(master, zone) # We need list of KSK's.
keys = ksks + zsks
trash = zone_trash_keys(master, zone)

# Check that move to the trash bin instead of delete works.
issetbr(len(trash) != 0, "some keys have been deleted")
issetbr(len(keys) != 0, "not all keys have been deleted")
comparebr(all_keys, set(keys + trash), "all keys metadata found (active and deleted)")
keystore_keys = kstore.keys()
comparebr(all_keys, set(keystore_keys), "all keys found in keystore (active and deleted)")

# Check that 'import-trash' works.
ksk = ksks[0]
check_key(master, zone, kstore, ksk, exists=True, trash=False)

Keymgr.run_check(master.confile, zone.name, "delete", ksk)
check_key(master, zone, kstore, ksk, exists=False, trash=True)

_, stdout, _ = Keymgr.run_check(master.confile, zone.name, "import-trash", ksk)
ksk_reimport = stdout.strip().splitlines()[0]
comparebr(ksk_reimport, ksk, f"deleted KSK key {ksk} reimported with the same Key ID")
check_key(master, zone, kstore, ksk, exists=True, trash=False)
cur_keys = zone_keys(master, zone)
cur_trash = zone_trash_keys(master, zone)
comparebr(set(keys), set(cur_keys), "keys did not change after delete/import-trash")
comparebr(set(trash), set(cur_trash), "trash did not change after delete/import-trash")
master.ctl("zone-sign %s" % zone.name, wait=True)
cur_ksks, cur_zsks = zone_ksks_zsks(master, zone)
comparebr(set(ksks), set(cur_ksks),
          "set of KSK's did not change after delete/import-trash/zone-sign")

# Check that 'trash-discard' works.
zsk_discarded = random.choice(trash)
Keymgr.run_check(master.confile, zone.name, "trash-discard", zsk_discarded)
check_key(master, zone, kstore, zsk_discarded, exists=False, trash=False)
cur_trash = list(set(trash) - {zsk_discarded})

master.ctl("zone-thaw", wait=True)

# The following checks require compile-time support in the knotd binary.
# -DTRASH_GC_INTERVAL=30   (./configure --with-gc-interval=30 ...)
if not check_gc_interval(master):
    check_log("TRASH_GC_INTERVAL not tuned, skipping trash garbage collector test")
else:
    # Let all known trash keys time out and wait for the next trash GC run.
    t.sleep(80)

    new_trash = zone_trash_keys(master, zone)
    new_kst_keys = kstore.keys()

    # Check that the background garbage collector works.
    for key_id in cur_trash:
        issetbr(key_id not in new_trash, f"key {key_id} removed from trash bin")
        issetbr(key_id not in new_kst_keys, f"key {key_id} removed from trash bin keystore")

t.end()
