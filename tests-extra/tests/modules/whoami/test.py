#!/usr/bin/env python3

''' Check 'whoami' query module functionality. '''

from dnstest.test import Test
from dnstest.module import ModWhoami

t = Test()
ModWhoami.check()

# IPv4 test configuration.
knot4 = t.server("knot", address="127.0.0.2")
zone4 = t.zone("whoami.domain.example.", storage=".")
t.link(zone4, knot4)
knot4.add_module(zone4, ModWhoami())

# IPv6 test configuration.
knot6 = t.server("knot", address=6)
zone6 = t.zone("whoami6.domain.example.", storage=".")
t.link(zone6, knot6)
knot6.add_module(zone6, ModWhoami())

t.start()

# IPv4 test.
resp = knot4.dig("whoami.domain.example", "NS")
resp.check(rcode="NOERROR", rdata="ns.whoami.domain.example.", ttl=86400)

resp = knot4.dig("whoami.domain.example", "A")
resp.check(rcode="NOERROR", rdata="127.0.0.1", ttl=1)

resp = knot4.dig("whoami.domain.example", "AAAA")
resp.check(rcode="NOERROR", ttl=1)
assert(resp.count() == 0)

# IPv6 test.
resp = knot6.dig("whoami6.domain.example", "NS")
resp.check(rcode="NOERROR", rdata="ns.whoami6.domain.example.", ttl=86400)

resp = knot6.dig("whoami6.domain.example", "AAAA")
resp.check(rcode="NOERROR", rdata="::1", ttl=1)

resp = knot6.dig("whoami6.domain.example", "A")
resp.check(rcode="NOERROR", ttl=1)
assert(resp.count() == 0)

t.end()
