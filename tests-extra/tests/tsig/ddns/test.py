#!/usr/bin/env python3

from dnstest.test import Test

t = Test(tsig=True, stress=False)

knot = t.server("knot")
zone = t.zone("example.com")
t.link(zone, knot, ddns=True)

t.start()

zone[0].name = "examPle.com"
update = knot.update(zone)
update.add("kNoT.ExamPle.com.", 60, "TXT", "test")
update.add("test.example.com.", 60, "TXT", "test")
update.send("NOERROR")

resp = knot.dig("knot.example.com.", "TXT")
resp.check(rcode="NOERROR", rdata="test")

t.end()
