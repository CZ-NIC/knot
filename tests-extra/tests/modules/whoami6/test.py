#!/usr/bin/env python3

''' Check 'whoami' query module functionality (IPv6). '''

from dnstest.test import Test
from dnstest.module import ModWhoami

t = Test(address=6)
ModWhoami.check()

knot = t.server("knot")
zone = t.zone("whoami6.domain.example.", storage=".")
t.link(zone, knot)

knot.add_module(zone, ModWhoami("default"))

t.start()

resp = knot.dig("whoami6.domain.example", "NS")
resp.check(rcode="NOERROR", rdata="ns.whoami6.domain.example.")

resp = knot.dig("whoami6.domain.example", "AAAA")
resp.check(rcode="NOERROR", rdata="::1")

resp = knot.dig("whoami6.domain.example", "A")
resp.check(rcode="NOERROR")
assert(resp.count() == 0)

t.end()
