#!/usr/bin/env python3
"""
Validate reproducible signatures.
"""

import os
import shutil
import os.path

from dnstest.test import Test
from dnstest.keys import Keymgr

t = Test()

ALGORITHM=13
keysize = "1024" if ALGORITHM < 11 else "256"

master = t.server("knot")
slave1 = t.server("knot")
slave2 = t.server("knot")

zone = t.zone("example.com.")

t.link(zone, master, slave1)
t.link(zone, master, slave2)

for z in zone:
    for s in [slave1, slave2]:
        s.dnssec(z).enable = True
        s.dnssec(z).manual = True
        s.dnssec(z).repro_sign = True

slave1.gen_confile() # needed for keymgr

slave1.key_gen(zone[0].name, algorithm=str(ALGORITHM), ksk="true", zsk="true", size=keysize)

shutil.copytree(slave1.keydir, slave2.keydir)

# hide zonefile, in order to let servers start slowly
ZFILE=master.zones[zone[0].name].zfile.path
ZFILE_ = ZFILE + "_"
os.rename(ZFILE, ZFILE_)

t.start()

# now un-hide zonefile, invoke load and NOTIFY, and let both slaves sign in same second!
os.rename(ZFILE_, ZFILE)
master.ctl("zone-reload")

slave1.zones_wait(zone)
t.sleep(1)

t.xfr_diff(slave1, slave2, zone)

t.end()

