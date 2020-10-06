#!/usr/bin/env python3

'''Test zone backup of many zones with multiple background workers.'''

from dnstest.test import Test
from dnstest.utils import *
import shutil
import random

t = Test()

zones = t.zone_rnd(40, records=10)

master = t.server("knot")
backup_dir = master.dir + "/backup"

t.link(zones, master)

for z in zones:
    master.dnssec(z).enable = True

t.start()
serials_init = master.zones_wait(zones)

master.ctl("zone-backup +backupdir %s" % backup_dir)
t.sleep(10)

for z in zones:
    master.ctl("zone-key-rollover %s zsk" % z.name)

master.zones_wait(zones, serials_init, equal=False, greater=True)

master.ctl("zone-restore +backupdir %s" % backup_dir)
master.zones_wait(zones, serials_init, equal=True, greater=False)

t.stop()
