#!/usr/bin/env python3

''' Check 'whoami' query module functionality (IPv4). '''

from dnstest.test import Test
from dnstest.module import ModWhoami

t = Test(address=4)
ModWhoami.check()

knot = t.server("knot")
zone = t.zone("whoami.domain.example.", storage=".")
t.link(zone, knot)

knot.add_module(zone, ModWhoami("default"))

t.start()

resp = knot.dig("whoami.domain.example", "NS")
resp.check(rcode="NOERROR", rdata="ns.whoami.domain.example.")

resp = knot.dig("whoami.domain.example", "A")
resp.check(rcode="NOERROR", rdata="127.0.0.1")

resp = knot.dig("whoami.domain.example", "AAAA")
resp.check(rcode="NOERROR")
assert(resp.count() == 0)

t.end()
