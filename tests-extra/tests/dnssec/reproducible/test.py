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

ALGORITHM=8

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

slave1.gen_confile() # needed for keymgr

slave1.key_gen("common", algorithm=str(ALGORITH), ksk="true", zsk="true")

shutil.copytree(slave1.keydir, slave2.keydir)

t.start()

slave1.zones_wait(zone)
t.sleep(1)

t.xfr_diff(slave1, slave2, zone)

t.end()
