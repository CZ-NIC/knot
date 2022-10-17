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
BATCH_MAX = 300
FIXED_ZONES = 2000

#t = Test(stress=False)
t = Test()

knot = t.server("knot")

#if knot.valgrind:
#    knot.semantic_check = False
knot.semantic_check = False

catz = t.zone("catalog1.", storage=".")
rzone = t.zone(".")
nuzone = t.zone("nu.", storage=".")

t.link(catz, knot)
t.link(rzone, knot)
t.link(nuzone, knot)
knot.cat_interpret(catz)
catalog_dir = os.path.join(knot.dir, "catalog")
os.mkdir(catalog_dir)

knot.dnssec(rzone).enable = True
knot.dnssec(nuzone).enable = True

knot.zonefile_load = "difference"
knot.zones["catalog1."].journal_content = "all"
knot.gen_confile()

t.start()

zonefile_src = os.path.join(t.data_dir, "generic.zone")

fixed_counter = 0

while fixed_counter < FIXED_ZONES:
    fixed_remains = FIXED_ZONES - fixed_counter
    up = knot.update(catz)
    for j in range(fixed_remains if (fixed_remains < BATCH_MAX) else BATCH_MAX):
        member_zone = "fixed_member%d." % fixed_counter
        fixed_counter += 1
        unique_id = hashlib.md5(member_zone.encode()).hexdigest()
        name = unique_id + ".zones"
##
        owner = name + "." + catz[0].name
        zonefile = os.path.join(catalog_dir, member_zone + "zone")
        shutil.copyfile(zonefile_src, zonefile)

        up.add(name, 0, "PTR", member_zone)
    up.try_send()


knot.ctl("zone-sign . nu.")


member_list = list()
zonefile_src = os.path.join(t.data_dir, "generic.zone")

# Prepare detailed list of possible members in advance.
for j in range(BATCH_MAX):
    member_zone = "member%d." % j
    unique_id = hashlib.md5(member_zone.encode()).hexdigest()
    name = unique_id + ".zones"
    owner = name + "." + catz[0].name
    zonefile = os.path.join(catalog_dir, member_zone + "zone")
    member_list += [(member_zone, name, owner, zonefile)]

knot.zone_wait(catz, udp=False, tsig=True)

for i in range(ROUNDS):
    batch = random.randrange(1, BATCH_MAX)
#    batch = BATCH_MAX

    knot.ctl("zone-sign . nu.")

    up_add = knot.update(catz)
    up_del = knot.update(catz)
    for j in range(batch):
##
        shutil.copyfile(zonefile_src, member_list[j][3])
        up_add.add(member_list[j][1], 0, "PTR", member_list[j][0])
        up_del.delete(member_list[j][1], "PTR", member_list[j][0])
    up_add.try_send()
    up_del.try_send()

    for j in range(batch):
        resp = knot.dig(member_list[j][2], "PTR", udp=False, tsig=True)
        try:
            resp.check(rcode="NXDOMAIN", nordata="PTR")
        except:
            set_err("MEMBER NOT DELETED FROM CATZ: %s" % member_list[j][0])

t.end()
