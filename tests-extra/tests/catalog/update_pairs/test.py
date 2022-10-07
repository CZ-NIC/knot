#!/usr/bin/env python3

'''Test of a fast consecutive addition to and removal from a catalog.'''

from dnstest.test import Test
from dnstest.utils import set_err, detail_log

import os
import random
import time
import hashlib
import threading
import shutil

ROUNDS = 20
BATCH = 30

t = Test(stress=False)

knot = t.server("knot")

if knot.valgrind:
    knot.semantic_check = False

catz = t.zone("catalog1.", storage=".")

t.link(catz, knot)
knot.cat_interpret(catz)

os.mkdir(knot.dir + "/catalog")

t.start()

knot.zone_wait(catz, udp=False, tsig=True)

for i in range(ROUNDS):
    up = knot.update(catz)
    for j in range(BATCH):
        zone_add = "member%d." % j
        name_hash = hashlib.md5(zone_add.encode()).hexdigest()

        shutil.copyfile(t.data_dir + "generic.zone" , knot.dir + "/catalog/" + zone_add + "zone")
        up.add(name_hash + ".zones", 0, "PTR", zone_add)
    up.try_send()

    up = knot.update(catz)
    for j in range(BATCH):
        zone_add = "member%d." % j
        name_hash = hashlib.md5(zone_add.encode()).hexdigest()

        up.delete(name_hash + ".zones", "PTR", zone_add)
    up.try_send()

    for j in range(BATCH):
        zone_add = "member%d." % j
        name_hash = hashlib.md5(zone_add.encode()).hexdigest()

        resp = knot.dig(name_hash + ".zones." + catz[0].name, "PTR", udp=False, tsig=True)
        try:
            resp.check(rcode="NXDOMAIN", nordata="PTR")
        except:
            set_err("MEMBER NOT DELETED FROM CATZ")

t.end()
