#!/usr/bin/env python3

'''Test of frequent updates to catalog, processed in batches.'''

from dnstest.test import Test
from dnstest.utils import set_err, detail_log

import os
import random
import time
import hashlib
import threading
import shutil

UPDATES = 132

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

check_names = list()

def send_update(up):
    try:
        up.try_send()
    except:
        pass

def send_up_bg(up):
    threading.Thread(target=send_update, args=[up]).start()

for i in range(UPDATES):
    zone_add = "member%d." % i
    name_hash = hashlib.md5(zone_add.encode()).hexdigest()

    shutil.copyfile(t.data_dir + "generic.zone" , knot.dir + "/catalog/" + zone_add + "zone")

    up = knot.update(catz)
    up.add(name_hash + ".zones", 0, "PTR", zone_add)
    send_up_bg(up)

    if i % 2 == 1:
        t.sleep(random.choice([1.5, 2, 2.5]))
    else:
        t.sleep(random.choice([0.1, 0.15, 0.25]))

    check_names += [ zone_add ]

t.sleep(4)

for n in check_names:
    resp = knot.dig(n, "SOA", udp=False, tsig=True)
    resp.check(rcode="NOERROR") # not REFUSED

if knot.log_search("catalog, interpreting 2 updates"):
    set_err("LOST UPD SIGNAL")

t.end()
