#!/usr/bin/env python3

from dnstest.test import Test

t = Test(tsig=True, stress=False)

knot = t.server("knot")
zone = t.zone("example.com")
t.link(zone, knot, ddns=True)

t.start()

update = knot.update(zone)
update.add("knot.example.com.", 60, "TXT", "test")
update.send("NOERROR")

resp = knot.dig("knot.example.com.", "TXT")
resp.check(rcode="NOERROR", rdata="test")

t.end()
