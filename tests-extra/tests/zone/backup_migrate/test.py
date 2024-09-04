#!/usr/bin/env python3

from dnstest.test import Test
from dnstest.utils import *
import filecmp

t = Test()

master1 = t.server("knot")
master2 = t.server("knot")
backup_dir = master1.dir + "/backup"

zone = t.zone_rnd(32, dnssec=False)

t.link(zone, master1, master2)

for z in zone:
    master1.dnssec(z).enable = True

t.start()

serial_m1_0 = master1.zones_wait(zone)
serial_m2_0 = master2.zones_wait(zone)

master1.ctl("zone-backup +backupdir %s +journal" % backup_dir, wait=True)

for z in zone:
    master2.zones[z.name].masters = set()
master2.gen_confile()

try:
    master2.ctl("zone-restore +backupdir %s +journal" % backup_dir, wait=True)
    master2.zones_wait(zone, serial_m1_0, equal=True)
    t.xfr_diff(master1, master2, zone)
except:
    t.sleep(50)
    master2.reload()
    t.sleep(30)
    t.xfr_diff(master1, master2, zone)

t.stop()
