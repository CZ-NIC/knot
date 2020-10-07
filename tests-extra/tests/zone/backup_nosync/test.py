#!/usr/bin/env python3

'''Test zone backup of a zone with flushing disabled.'''

from dnstest.test import Test
from dnstest.utils import *
import filecmp

t = Test()

master1 = t.server("knot")
master2 = t.server("knot")
backup_dir = master1.dir + "/backup"

zone = t.zone("example.com.")

t.link(zone, master1)
t.link(zone, master2)

master1.dnssec(zone[0]).enable = True
master1.zonefile_sync = -1

t.start()

serial_m1_0 = master1.zone_wait(zone)
serial_m2_0 = master2.zone_wait(zone)

master1.ctl("zone-backup +backupdir %s +journal" % backup_dir, wait=True)

# Restore zone file only without journal -> different zone contents
master2.ctl("zone-restore +backupdir %s" % backup_dir, wait=True)
serial_m2_1 = master2.zone_wait(zone)
compare(serial_m2_1, serial_m2_0, "zones differ")
zfiles_diff = filecmp.cmp(master1.zones[zone[0].name].zfile.path, \
                          master2.zones[zone[0].name].zfile.path, shallow=True)
isset(zfiles_diff, "zone files differ")

# Restore zone file and journal -> same zone contents
master2.ctl("zone-restore +backupdir %s +journal" % backup_dir, wait=True)
serial_m2_2 = master2.zone_wait(zone)
compare(serial_m2_2, serial_m1_0, "zones differ")
zfiles_diff = filecmp.cmp(master1.zones[zone[0].name].zfile.path, \
                          master2.zones[zone[0].name].zfile.path, shallow=True)
isset(zfiles_diff, "zone files differ")

t.xfr_diff(master1, master2, zone)

t.stop()
