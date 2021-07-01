#!/usr/bin/env python3

'''Test that backup locking and labelling work in backup and restore.'''

from dnstest.test import Test
from dnstest.utils import *
import random
import os

def wait_for_file(file, timeout=10):
    '''Wait for a file, with timeout'''

    for i in range(int(timeout / 0.2)):
        if os.path.isfile(file):
            break
        time.sleep(0.2)

t = Test()

master = t.server("knot")
backup_dir = os.path.join(master.dir, "backup")
backup_dir_void = os.path.join(master.dir, "backup_void")

# WIP:
# The test must be tuned for ASAN on a fast test server.
#zone_records = 80 if master.valgrind else 500
#zones = t.zone_rnd(40 if master.valgrind else 300, records=zone_records)

zones = t.zone_rnd(40, records=80)

t.link(zones, master)

# WIP:
#master2 = t.server("knot")
#zones2 = t.zone("example1.") + t.zone("example2.") + t.zone("example3.")
#t.link(zones2, master2)
#backup2_dir = os.path.join(master2.data_dir, "backup2")
#backup3_dir = os.path.join(master2.data_dir, "backup3")
#backup4_dir = os.path.join(master2.data_dir, "backup4")
#backup5_dir = os.path.join(master2.data_dir, "backup5")
#backup6_dir = os.path.join(master2.data_dir, "backup6")

if master.valgrind:
    master.ctl_params_append = ["-t", "240"]

lockfile = os.path.join(backup_dir, "lock.knot_backup")
labelfile = os.path.join(backup_dir, "knot_backup.label")

t.start()
serials_init = master.zones_wait(zones)

for i in range(10):
    for zone in zones:
        master.random_ddns(zone)

master.ctl("zone-backup +journal +backupdir %s" % backup_dir, wait=False)
wait_for_file(lockfile, timeout=5)
if master.valgrind:   # WIP: temporary vorkaround for a too fast test server with ASAn
    # Attempt to start concurrent backups, expected (requested resource is busy).
    try:
        master.ctl("zone-backup +backupdir %s" % backup_dir, wait=True)
        set_err("CONCURRENT BACKUPS ALLOWED")
    except:
        pass
    # Attempt to start concurrent backup and restore, expected (malformed data).
    try:
        master.ctl("zone-restore +backupdir %s" % backup_dir, wait=True)
        set_err("RESTORE FROM A PENDING BACKUP ALLOWED")
    except:
        pass

wait_for_file(labelfile, timeout=60)

# Attempt to start backup into already existing backup, expected (already exists).
try:
    master.ctl("zone-backup +backupdir %s" % backup_dir, wait=True)
    set_err("BACKUP INTO EXISTING BACKUP ALLOWED")
except:
    pass

# Attempt to start restore from non-existing backup directory, expected (not exists).
try:
    master.ctl("zone-restore +backupdir %s" % backup_dir_void, wait=True)
    set_err("RESTORE FROM NON-EXISTING DIRECTORY ALLOWED")
except:
    pass

# Attempt to start backup to the database storage directory, expected (invalid parameter).
try:
    master.ctl("zone-backup +backupdir %s" % master.dir, wait=True)
    set_err("BACKUP TO THE DB STORAGE DIRECTORY ALLOWED")
except:
    pass

# Attempt to start restore from the database storage directory, expected (invalid parameter).
try:
    master.ctl("zone-restore +backupdir %s" % master.dir, wait=True)
    set_err("RESTORE FROM THE DB STORAGE DIRECTORY ALLOWED")
except:
    pass

# Attempt to start restore from a non-backup directory, expected (malformed data).
try:
    master.ctl("zone-restore +backupdir %s" % t.out_dir, wait=True)
    set_err("RESTORE FROM A NON-BACKUP DIRECTORY ALLOWED")
except:
    pass

# Do a regular restore, expected OK.
try:
    master.ctl("zone-restore +backupdir %s" % backup_dir, wait=True)
except:
    set_err("RESTORE NOT ALLOWED")

# Do a regular restore with the "-f" option from the current format, expected OK.
try:
    master.ctl("-f zone-restore +backupdir %s" % backup_dir, wait=True)
except:
    set_err("RESTORE NOT ALLOWED")

# Tests with preconfigured backups, server master2. #############################

# Attempt to restore without the "-f" option from the format 1 backup, expected (malformed data).
try:
    master2.ctl("zone-restore +backupdir %s" % backup2_dir, wait=True)
    set_err("RESTORE FROM OBSOLETE FORMAT ALLOWED")
except:
    pass

# Do a restore with the "-f" option from a format 1 backup, expected OK.
try:
    master2.ctl("-f zone-restore +backupdir %s" % backup2_dir, wait=True)
except:
    set_err("FORCED RESTORE FROM OBSOLETE FORMAT NOT ALLOWED")

# Attempt to restore from a labelled, but locked backup, expected (requested resource is busy).
try:
    master2.ctl("-f zone-restore +backupdir %s" % backup3_dir, wait=True)
    set_err("RESTORE FROM A LOCKED BACKUP ALLOWED")
except:
    pass

# Attempt to restore from an unlabelled backup, expected (malformed data).
try:
    master2.ctl("-f zone-restore +backupdir %s" % backup4_dir, wait=True)
    set_err("RESTORE FROM AN UNLABELLED BACKUP ALLOWED")
except:
    pass

# Attempt to restore from a backup with corrupted label, expected (malformed data).
try:
    master2.ctl("-f zone-restore +backupdir %s" % backup5_dir, wait=True)
    set_err("RESTORE FROM BACKUP WITH A CORRUPT LABEL ALLOWED")
except:
    pass

# Attempt to restore from unsupported backup format number, expected (malformed data).
try:
    master2.ctl("-f zone-restore +backupdir %s" % backup6_dir, wait=True)
    set_err("RESTORE FROM UNSUPPORTED BACKUP FORMAT VERSION ALLOWED")
except:
    pass

t.stop()
