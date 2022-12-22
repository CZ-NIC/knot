#!/usr/bin/env python3

"""
Validate reproducible signatures.
"""

import os
import shutil
import os.path
import random
import time

from dnstest.test import Test
from dnstest.keys import Keymgr
from dnstest.utils import *

t = Test()

master = t.server("knot")
slave1 = t.server("knot")
slave2 = t.server("knot")

zone = t.zone("example.com.")

t.link(zone, master, slave1)
t.link(zone, master, slave2)

algorithms = [
        { 'code': 13, 'name': 'ECDSAP256SHA256', 'always_reproducible': False },
        { 'code': 15, 'name': 'ED25519',         'always_reproducible': True  },
        { 'code': 16, 'name': 'ED448',           'always_reproducible': True  }
]

alg = random.choice(algorithms)

for z in zone:
    for s in [slave1, slave2]:
        s.dnssec(z).enable = True
        s.dnssec(z).manual = True
        s.dnssec(z).alg = alg['name']
        s.dnssec(z).repro_sign = not alg['always_reproducible']

slave1.gen_confile() # needed for keymgr

slave1.key_gen(zone[0].name, algorithm=str(alg['code']), ksk="true", zsk="true")

slave2keydir = slave2.keydir
os.rmdir(slave2keydir)
shutil.copytree(slave1.keydir, slave2keydir)

# hide zonefile, in order to let servers start slowly
ZFILE=master.zones[zone[0].name].zfile.path
ZFILE_ = ZFILE + "_"
os.rename(ZFILE, ZFILE_)

t.start()

# ensure the test starts at the beginning of a second
while round((time.time()%1) * 100) > 1:
    time.sleep(0.01)

# now un-hide zonefile, invoke load and NOTIFY, and let both slaves sign in same second!
os.rename(ZFILE_, ZFILE)
master.ctl("zone-reload")

serial_orig = slave1.zone_wait(zone)
t.sleep(1)

t.xfr_diff(slave1, slave2, zone)

# now stop and start slave1 and check if it doesn't re-sign the zone
slave1.stop()
t.sleep(3)
slave1.start()

serial = slave1.zone_wait(zone)
if serial != serial_orig:
    set_err("zone was re-signed")

t.end()

