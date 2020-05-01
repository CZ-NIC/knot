#!/usr/bin/env python3

'''Test for checking zone size limit with IXFR update'''

from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")
zone = t.zone("example.com.")
slave.zone_size_limit = 500

t.link(zone, master, slave, ddns=True)
t.start()

slave.zones_wait(zone)

update = master.update(zone)
update.add("test.example.com.", 1, "TXT", "passed")
update.send("NOERROR")

t.sleep(5)
resp = slave.dig("test.example.com.", "TXT")
resp.check("passed")

update = master.update(zone)
update.add("test.example.com.", 1, "TXT", "FAILED. This zone is larger than limit. More text: Lorem impsum dolor sit a met.")
update.delete("test.example.com.", "TXT", "passed")
update.send("NOERROR")

t.sleep(5)
resp = slave.dig("test.example.com.", "TXT")
resp.check("passed")

t.end()
