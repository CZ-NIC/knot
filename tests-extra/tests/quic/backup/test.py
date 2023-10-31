#!/usr/bin/env python3

'''Test of QUIC auto-generated key backup and restore.'''

from dnstest.test import Test
from dnstest.utils import *

t = Test(quic=True)

master = t.server("knot")
zones = t.zone("example.")
t.link(zones, master)

DFLT_QUIC_KEY_FILE = "quic_key.pem"

backup_dir = os.path.join(master.dir, "backup")
backup_dir2 = os.path.join(master.dir, "backup2")
keyfile = os.path.join(master.dir, "keys", DFLT_QUIC_KEY_FILE)
backup_keyfile = os.path.join(backup_dir, "keys", DFLT_QUIC_KEY_FILE)

master.check_quic()

t.start()

master.zones_wait(zones)
t.sleep(1)
master.fill_cert_key()
key1_pin = master.cert_key

master.ctl("zone-backup +quic +backupdir %s" % backup_dir, wait=True)
os.remove(keyfile)

master.stop()
master.start()

master.zones_wait(zones)
t.sleep(1)
master.fill_cert_key()
key2_pin = master.cert_key

if key1_pin == key2_pin:
    set_err("NEW KEY NOT GENERATED")

master.ctl("zone-restore +quic +backupdir %s" % backup_dir, wait=True)

master.stop()
master.start()

master.zones_wait(zones)
t.sleep(1)
master.fill_cert_key()
key3_pin = master.cert_key

if key1_pin != key3_pin:
    set_err("BACKED UP KEY NOT RESTORED")

# Backup of an actively used QUIC key (i.e. QUIC is turned on and no user
# QUIC key is defined) must fail if the key file is non-existent.
os.remove(keyfile)
try:
    master.ctl("zone-backup +quic +backupdir %s" % backup_dir2, wait=True)
    set_err("BACKUP OF A MISSING KEY ALLOWED")
except:
    pass

# Restore of an actively used QUIC key (i.e. QUIC is turned on and no user
# QUIC key is defined) must fail if the key is missing from the backup.
os.remove(backup_keyfile)
try:
    master.ctl("zone-restore +quic +backupdir %s" % backup_dir, wait=True)
    set_err("RESTORE OF A MISSING BACKUP KEY ALLOWED")
except:
    pass

t.end()
