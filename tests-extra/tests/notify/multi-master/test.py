#!/usr/bin/env python3

'''Test for NOTIFY scheduling upon refresh from one of more masters'''

import shutil
from dnstest.test import Test

t = Test()

master1 = t.server("knot")
master2 = t.server("knot")
signer = t.server("knot")
slave = t.server("knot")
zones = t.zone("example.com.") + t.zone_rnd(1, records=20)

t.link(zones, master1, signer, ixfr=True)
t.link(zones, master2, signer, ixfr=True)
t.link(zones, signer, slave, ixfr=True)

master1.disable_notify = True
master2.disable_notify = True

t.start()

serials_init = slave.zones_wait(zones)

for zone in zones:
    master1.update_zonefile(zone, random=True)
    zf1 = master1.zones[zone.name].zfile.path
    zf2 = master2.zones[zone.name].zfile.path
    shutil.copyfile(zf1, zf2)
master1.reload()
master2.reload()

t.sleep(5)
slave.zones_wait(zones, serials_init, equal=True, greater=False)

signer.ctl("zone-refresh")

slave.zones_wait(zones, serials_init)

t.end()
