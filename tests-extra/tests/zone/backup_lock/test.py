#!/usr/bin/env python3

'''Test that backup locking and labelling work in backup and restore.'''

from dnstest.test import Test
from dnstest.utils import *
import random
import os
import shutil

def wait_for_file(file, timeout=10):
    '''Wait for a file, with timeout'''

    for i in range(int(timeout / 0.2)):
        if os.path.isfile(file):
            break
        time.sleep(0.2)

def log_errcode(s):
    a = s.rfind("(")
    b = s.rfind(")")
    if a >= b or a < 0:
        return ""
    return s[a+1:b]

def check_log_err(server, expect_err):
    with open(server.fout) as logf:
        for logline in logf:
            if "error:" in logline:
                last_log = logline
    if log_errcode(last_log) != expect_err:
        set_err("WRONG ERRCODE")
        detail_log("!Unexpected errcode '%s' != '%s'" % (log_errcode(last_log), expect_err))

t = Test()

master = t.server("knot")
backup_dir = os.path.join(master.dir, "backup")
backup_dir_void = os.path.join(master.dir, "backup_void")

zones = t.zone_rnd(40, records=80)

t.link(zones, master)

master2 = t.server("knot")
zones2 = t.zone("example1.", file_name="example1.file", storage=".")  \
         + t.zone("example2.", file_name="example2.file", storage=".") \
         + t.zone("example3.", file_name="example3.file", storage=".")
t.link(zones2, master2)
for i in range(2, 8):
    dir_from = os.path.join(t.data_dir, "backup%d" % i)
    dir_to = os.path.join(master2.dir, "backup%d" % i)
    shutil.copytree(dir_from, dir_to)
    globals()["backup%d_dir" % i] = dir_to

if master.valgrind:
    master.ctl_params_append = ["-t", "40"]

lockfile = os.path.join(backup_dir, "lock.knot_backup")
labelfile = os.path.join(backup_dir, "knot_backup.label")

if master.valgrind:
    master.semantic_check = False
    master2.semantic_check = False

t.start()
serials_init = master.zones_wait(zones)

for i in range(10):
    for zone in zones:
        master.random_ddns(zone)

master.ctl("zone-backup +journal +backupdir %s" % backup_dir, wait=False)
wait_for_file(lockfile, timeout=5)
if master.valgrind:   # Without Valgrind the backup is too fast for this test-case
    # Attempt to start concurrent backups, expected (requested resource is busy).
    try:
        master.ctl("zone-backup +backupdir %s" % backup_dir, wait=True)
        set_err("CONCURRENT BACKUPS ALLOWED")
    except:
        pass
    check_log_err(master, "requested resource is busy")
    # Attempt to start a restore from a backup in progress, expected (malformed data).
    try:
        master.ctl("zone-restore +backupdir %s" % backup_dir, wait=True)
        set_err("RESTORE FROM A PENDING BACKUP ALLOWED")
    except:
        pass
    check_log_err(master, "malformed data")

wait_for_file(labelfile, timeout=60)

# Attempt to start backup into already existing backup, expected (already exists).
try:
    master.ctl("zone-backup +backupdir %s" % backup_dir, wait=True)
    set_err("BACKUP INTO EXISTING BACKUP ALLOWED")
except:
    pass
check_log_err(master, "already exists")

# Attempt to start restore from non-existing backup directory, expected (not exists).
try:
    master.ctl("zone-restore +backupdir %s" % backup_dir_void, wait=True)
    set_err("RESTORE FROM NON-EXISTING DIRECTORY ALLOWED")
except:
    pass
check_log_err(master, "not exists")

# Attempt to start backup to the database storage directory, expected (invalid parameter).
try:
    master.ctl("zone-backup +backupdir %s" % master.dir, wait=True)
    set_err("BACKUP TO THE DB STORAGE DIRECTORY ALLOWED")
except:
    pass
check_log_err(master, "invalid parameter")

# Attempt to start restore from the database storage directory, expected (invalid parameter).
try:
    master.ctl("zone-restore +backupdir %s" % master.dir, wait=True)
    set_err("RESTORE FROM THE DB STORAGE DIRECTORY ALLOWED")
except:
    pass
check_log_err(master, "invalid parameter")

# Attempt to start restore from a non-backup directory, expected (malformed data).
try:
    master.ctl("zone-restore +backupdir %s" % t.out_dir, wait=True)
    set_err("RESTORE FROM A NON-BACKUP DIRECTORY ALLOWED")
except:
    pass
check_log_err(master, "malformed data")

# Do a regular restore, expected OK.
try:
    master.ctl("zone-restore +backupdir %s" % backup_dir, wait=True)
except:
    set_err("RESTORE NOT ALLOWED")

# Do a regular restore with the "-f" option from the current format, expected OK.
try:
    master.ctl("-f zone-restore +backupdir %s" % backup_dir, wait=True)
except:
    set_err("FORCED RESTORE NOT ALLOWED")

# Tests with preconfigured backups, server master2. #############################

# Attempt to restore without the "-f" option from the format 1 backup, expected (malformed data).
try:
    master2.ctl("zone-restore +backupdir %s" % backup2_dir, wait=True)
    set_err("RESTORE FROM OBSOLETE FORMAT ALLOWED")
except:
    pass
check_log_err(master2, "malformed data")

# Do a restore with the "-f" option from a format 1 backup, expected OK.
try:
    master2.ctl("-f zone-restore +backupdir %s" % backup2_dir, wait=True)
except:
    set_err("FORCED RESTORE FROM OBSOLETE FORMAT NOT ALLOWED")

# Attempt to restore from a labelled, but locked backup, expected (requested resource is busy).
try:
    master2.ctl("zone-restore +backupdir %s" % backup3_dir, wait=True)
    set_err("RESTORE FROM A LOCKED BACKUP ALLOWED")
except:
    pass
check_log_err(master2, "requested resource is busy")

# Attempt to restore from an unlabelled backup, expected (malformed data).
try:
    master2.ctl("zone-restore +backupdir %s" % backup4_dir, wait=True)
    set_err("RESTORE FROM AN UNLABELLED BACKUP ALLOWED")
except:
    pass
check_log_err(master2, "malformed data")

# Attempt to restore from a backup with corrupted label, expected (malformed data).
try:
    master2.ctl("-f zone-restore +backupdir %s" % backup5_dir, wait=True)
    set_err("RESTORE FROM BACKUP WITH A CORRUPT LABEL ALLOWED")
except:
    pass
check_log_err(master2, "malformed data")

# Attempt to restore from unsupported backup format number, expected (operation not supported).
try:
    master2.ctl("-f zone-restore +backupdir %s" % backup6_dir, wait=True)
    set_err("RESTORE FROM UNSUPPORTED BACKUP FORMAT VERSION ALLOWED")
except:
    pass
check_log_err(master2, "operation not supported")

# Attempt to restore from non-existant backup format number, expected (malformed data).
try:
    master2.ctl("-f zone-restore +backupdir %s" % backup7_dir, wait=True)
    set_err("RESTORE FROM NON-EXISTANT BACKUP FORMAT VERSION ALLOWED")
except:
    pass
check_log_err(master2, "malformed data")

t.stop()
