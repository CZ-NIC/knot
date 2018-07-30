#!/usr/bin/env python3

'''geoip module functionality test'''

import dns.exception
import dns.message
import dns.query
import dns.edns
import dns.rrset
import dns.rdata
import dns.rdatatype
import dns.rdataclass
import dns.name
import os
import time

from dnstest.test import Test
from dnstest.module import ModGeoip
from dnstest.utils import *

# ECS option: 2 bytes AF, 1 byte source, 1 byte scope, variable length subnet

ecs_wire = bytearray(b'\x00\x01\x20\x00\x01\x02\x03\x04')
ecs_wire_len = 8
ecs_opt_code = 8
ecs_opt = dns.edns.option_from_wire(ecs_opt_code, ecs_wire, 0, ecs_wire_len)

ModGeoip.check()

t = Test(stress=False)

knot = t.server("knot")
zone = t.zone("example.com.", storage=".")

t.link(zone, knot)

t.start()

knot.clear_modules(None)

mod_geoip = ModGeoip(t.data_dir + "/geo.conf", "geodb", t.data_dir + "/db.mmdb", ["country/iso_code", "(id)city/geoname_id"])

knot.add_module(zone, mod_geoip);
knot.gen_confile()
knot.reload()
knot.zone_wait(zone)

qname = dns.name.from_text("foo.example.com.")
geo_query = dns.message.make_query(qname, "A", use_edns=True, options=[ecs_opt])
response = dns.query.udp(geo_query, knot.addr, port=knot.port, timeout=1)
compare(response.rcode(), 0, "QUERY FAILED")
rrset = response.get_rrset(response.answer, qname, dns.rdataclass.IN, dns.rdatatype.A)
rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "1.2.3.4")
found = False
for rd in rrset:
    print(rd.to_text())
    if rd == rdata:
        found = True
compare(found, True, "NO CORRECT ANSWER")




