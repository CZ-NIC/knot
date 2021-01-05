#!/usr/bin/env python3

'''Test that Knot is able to load records that it's able to dump to zone file.'''

from dnstest.test import Test
from dnstest.utils import set_err, detail_log
import os,shutil

t = Test()

knota = t.server("knot")
knotb = t.server("knot")

zones = t.zone("example.", storage=".")

t.link(zones, knota)
t.link(zones, knotb)

t.generate_conf()

knota.start()
knota.zones_wait(zones)

for z in zones:
    zfilea = knota.zones[z.name].zfile.path
    os.remove(zfilea) # make sure zone file won't exist if flush fails

knota.ctl("-f zone-flush", wait=True)

for z in zones:
    zfilea = knota.zones[z.name].zfile.path
    zfileb = knotb.zones[z.name].zfile.path
    shutil.copyfile(zfilea, zfileb)

knotb.start()
knotb.zones_wait(zones)

t.xfr_diff(knota, knotb, zones)
t.end()
