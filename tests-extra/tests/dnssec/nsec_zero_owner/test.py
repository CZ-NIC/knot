#!/usr/bin/env python3

'''Test of handling wrong NSEC tree due to \000 '''

from dnstest.utils import *
from dnstest.test import Test

t = Test()

master = t.server("knot")
zone = t.zone("example.com.")

t.link(zone, master)

for z in zone:
    master.dnssec(z).enable = True
    master.dnssec(z).nsec3 = False

t.start()
master.zones_wait(zone)

up = master.update(zone)
up.add("ab\000cd.example.com.", 3600, "A", "1.2.4.3")
up.send()
t.sleep(2)

resp = master.dig("ab\000cd.example.com.", "A")
resp.check(rcode="NOERROR")

up = master.update(zone)
up.add("ce.ab.example.com.", 3600, "A", "1.2.4.3")
up.send(rcode="SERVFAIL")
t.sleep(2)

resp = master.dig("ce.ab.example.com.", "A")
resp.check(rcode="NXDOMAIN")

t.end()
