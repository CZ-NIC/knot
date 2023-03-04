#!/usr/bin/env python3

'''Test for concurrent addition of generated catalog and its member zone.'''

from dnstest.utils import *
from dnstest.test import Test
import random

def add_catalog(t, master, slave):
    cnt = random.choice([0, 1, 5, 10])
    if cnt == 0:
        detail_log("No new catalog")
        return (list(), list())

    catz = t.zone_rnd(1, exists=False)
    members = t.zone_rnd(cnt, dnssec=False, records=1)

    t.link(catz + members, master, slave)

    master.cat_generate(catz)
    slave.cat_interpret(catz)

    for mem in members:
        master.cat_member(mem, catz)
        slave.cat_hidden(mem)

    detail_log("New catalog %s, member count %i" % (catz[0].name, cnt))
    return (catz, members)

t = Test()

master = t.server("knot")
slave = t.server("knot")

master.zonefile_sync = "0" # Not needed, just to ensure catalog with up-to-date zone file.

(cat0, memb0) = add_catalog(t, master, slave)

t.start()

(cat1, memb1) = add_catalog(t, master, slave)
(cat2, memb2) = add_catalog(t, master, slave)

master.gen_confile()
slave.gen_confile()

add_online = random.choice([True, False])
slave.reload()
if add_online:
    master.reload()
else:
    master.stop()
    t.sleep(1)
    master.start()

slave.zones_wait(memb0 + memb1 + memb2)

t.end()
