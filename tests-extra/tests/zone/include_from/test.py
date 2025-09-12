#!/usr/bin/env python3

"""
Test of flattening subzones.
"""

from dnstest.utils import *
from dnstest.test import Test
import random

t = Test()

master = t.server("knot") # if not tld_axfr: only providing the subzones
flattener = t.server("knot")
slave = t.server("knot") # only slaving the flattened zone

parent = t.zone("cz.", storage=".")
childs = t.zone("com.cz.", storage=".") + t.zone("net.cz.", storage=".") + t.zone("org.cz.", storage=".")

tld_axfr = random.choice([False, True])

t.link(childs, master, flattener)
t.link(parent, flattener, slave)

if tld_axfr:
    t.link(parent, master, flattener)

parent_master = master if tld_axfr else flattener

flattener.zones[parent[0].name].include_from = childs

flattener.dnssec(parent).enable = random.choice([False, True])

t.start()
serial = slave.zone_wait(parent)

for z in childs:
    for ty in [ "SOA", "NS", "DS", "CDS" ]:
        r = slave.dig(z.name, ty)
        r.check(rcode="NOERROR")
        r.check_count(0, ty)
    r = slave.dig("dns1." + z.name, "A")
    r.check(rcode="NOERROR", rdata="192.0.2.1")

r = slave.dig("dns1.org.cz", "A")
r.check(rcode="NOERROR", rdata="192.0.2.2")

r = slave.dig("com.cz.", "TXT")
r.check(rcode="NOERROR", rdata="auth-txt")
r.check(rcode="NOERROR", rdata="nonauth-txt")
r.check_count(2, "TXT")

up = master.update(childs[0])
up.add("dns1", 3600, "AAAA", "1::2")
up.send("NOERROR")

serial = slave.zone_wait(parent, serial)
r = slave.dig("dns1.com.cz.", "AAAA")
r.check(rcode="NOERROR", rdata="1::2")

parent_zf = parent_master.zones[parent[0].name].zfile
parent_zf.append_rndTXT("txt.cz.", rdata="added-txt")
parent_zf.update_soa()
if tld_axfr or random.choice([False, True]):
    parent_master.ctl("zone-reload " + parent[0].name)
else:
    up = master.update(childs[1])
    up.add("anything", 3600, "TXT", "dontcare")
    up.send("NOERROR")

serial = slave.zone_wait(parent, serial)
r = slave.dig("txt.cz.", "TXT")
r.check(rcode="NOERROR", rdata="added-txt")

invalid_conf = random.choice(["include_self", "include_parent", "also_reverse"])
if invalid_conf == "include_self":
    flattener.zones[parent[0].name].include_from = parent
elif invalid_conf == "include_parent":
    flattener.zones[childs[0].name].include_from = parent
else:
    flattener.zones[parent[0].name].reverse_from = childs
flattener.gen_confile()
try:
    flattener.reload()
    set_err("INVALID CONF ACCEPTED: " + invalid_conf)
except:
    pass

t.end()
