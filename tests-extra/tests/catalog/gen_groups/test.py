#!/usr/bin/env python3

'''Test of Catalog zone generation with configuration groups.'''

from dnstest.test import Test
from dnstest.utils import set_err, detail_log
import os
import random
import time

t = Test()

def wait_for_zonefile(server, role, zonename, max_age, timeout):
    fn = os.path.join(server.dir, role, zonename + "zone")
    while timeout > 0:
        if os.path.exists(fn):
            age = time.time() - os.path.getmtime(fn)
        else:
            age = max_age + 1
        if age <= max_age:
            break
        timeout -= 1
        t.sleep(1)
    t.sleep(max_age)

master = t.server("knot")
slave = t.server("knot")

catz = t.zone("example.")
zone = t.zone_rnd(2, dnssec=False)

t.link(catz, master, slave)
t.link(zone, master, slave)

master.cat_generate(catz)
slave.cat_interpret(catz)
master.cat_member(zone[0], catz, "catalog-signed")
slave.cat_hidden(zone[0])
master.cat_member(zone[1], catz, "catalog-unsigned")
slave.cat_hidden(zone[1])

t.start()

slave.zones_wait(zone)

master.ctl("zone-status")
slave.ctl("zone-status")
resp = slave.dig(zone[0].name, "SOA", dnssec=True)
resp.check(rcode="NOERROR")
resp.check_count(1, "RRSIG")
resp = slave.dig(zone[1].name, "SOA", dnssec=True)
resp.check(rcode="NOERROR")
resp.check_count(0, "RRSIG")

master.cat_member(zone[1], catz, "catalog-signed")
master.gen_confile()
master.reload()

slave.flush()

t.sleep(8)
master.ctl("zone-status +catalog")
slave.ctl("zone-status +catalog")
resp = slave.dig(zone[1].name, "SOA", dnssec=True)
resp.check(rcode="NOERROR")
resp.check_count(1, "RRSIG")

t.end()
