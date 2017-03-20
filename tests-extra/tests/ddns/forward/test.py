#!/usr/bin/env python3

'''Test for DDNS forwarding'''

from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")
zone = t.zone("example.com.")

t.link(zone, master, slave, ddns=True)

t.start()

master.zones_wait(zone)
slave.zones_wait(zone)

# OK
update = slave.update(zone)
update.add("forwarded.example.com.", 1, "TXT", "forwarded")
update.send("NOERROR")
resp = master.dig("forwarded.example.com.", "TXT")
resp.check("forwarded")
t.sleep(2)
t.xfr_diff(master, slave, zone)

# NAME out of zone
update = slave.update(zone)
update.add("forwarded.", 1, "TXT", "forwarded")
update.send("NOTZONE")
resp = master.dig("forwarded.", "TXT")
resp.check(rcode="REFUSED")
t.sleep(2)
t.xfr_diff(master, slave, zone)

t.end()
