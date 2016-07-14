#!/usr/bin/env python3

'''Test for checking zone size limit with DDNS update'''

from dnstest.test import Test

t = Test()

master = t.server("knot")
zone = t.zone("example.com.")
master.zone_size_limit = 500

t.link(zone, master, ddns=True)
t.start()

master.zones_wait(zone)

update = master.update(zone)
update.add("test.example.com.", 1, "TXT", "passed")
update.send("NOERROR")
resp = master.dig("test.example.com.", "TXT")
resp.check("passed")

t.sleep(5)

update = master.update(zone)
update.add("test.example.com.", 1, "TXT", "FAILED. This zone is larger than limit. More text: Lorem impsum dolor sit a met.")
update.delete("test.example.com.", "TXT", "passed")
update.send("REFUSED")
resp = master.dig("test.example.com.", "TXT")
resp.check("passed")

t.end()
