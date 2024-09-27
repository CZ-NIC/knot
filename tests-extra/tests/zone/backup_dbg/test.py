#!/usr/bin/env python3

'''Test zone backup.'''

from dnstest.test import Test
from dnstest.module import ModOnlineSign
from dnstest.utils import *
from dnstest.keys import Keymgr
import shutil
import random

t = Test()

zones = t.zone("example.", storage=".") + t.zone("serial.", storage=".")
master = t.server("knot")
t.link(zones, master)

backup_dir = master.dir + "/backup"

t.start()
master.zones_wait(zones)

ZONE = zones[0].name
for i in range(100):
    master.ctl("-f zone-backup  +backupdir %s %s" % (backup_dir, ZONE), wait=True)
    master.ctl("zone-restore +backupdir %s %s" % (backup_dir, ZONE), wait=True)

for i in range(100):
    master.ctl("-f zone-backup  +backupdir %s" % (backup_dir), wait=True)
    master.ctl("zone-restore +backupdir %s" % (backup_dir), wait=True)

t.stop()
