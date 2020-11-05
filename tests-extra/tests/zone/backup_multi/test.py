#!/usr/bin/env python3

'''Test zone backup of many zones with multiple background workers.'''

from dnstest.test import Test
from dnstest.utils import *

t = Test()

zones = t.zone_rnd(40, records=10)

master = t.server("knot")
backup_dir = master.dir + "/backup"

t.link(zones, master)

for z in zones:
    master.dnssec(z).enable = True

if master.valgrind:
    master.ctl_params_append = ["-t", "240"]

t.start()
serials_init = master.zones_wait(zones)

for i in range(10):
    try:
        master.ctl("zone-backup +backupdir %s" % backup_dir)
    except:
        pass
    t.sleep(i * 0.05)
t.sleep(10)

for z in zones:
    master.ctl("zone-key-rollover %s zsk" % z.name)

master.zones_wait(zones, serials_init, equal=False, greater=True)

master.ctl("zone-restore +backupdir %s" % backup_dir, wait=True)
if master.valgrind:
    t.sleep(45);

master.zones_wait(zones, serials_init, equal=True, greater=False)

t.stop()
