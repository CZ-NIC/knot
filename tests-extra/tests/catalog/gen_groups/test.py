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
t.link(zone, master)

for z in zone:
    master.zones[z.name].catalog_gen_link(master.zones[catz[0].name])

master.zones[zone[0].name].catalog_group = "catalog-signed"
master.zones[zone[1].name].catalog_group = "catalog-unsigned"

slave.zones[catz[0].name].catalog = True

t.start()

slave.zones_wait(zone)

resp = slave.dig(zone[0].name, "SOA", dnssec=True)
resp.check(rcode="NOERROR")
resp.check_count(1, "RRSIG")
resp = slave.dig(zone[1].name, "SOA", dnssec=True)
resp.check(rcode="NOERROR")
resp.check_count(0, "RRSIG")

master.zones[zone[1].name].catalog_group = "catalog-signed"
master.gen_confile()
master.reload()

slave.flush()

t.sleep(8)
resp = slave.dig(zone[1].name, "SOA", dnssec=True)
resp.check(rcode="NOERROR")
resp.check_count(1, "RRSIG")

t.end()
