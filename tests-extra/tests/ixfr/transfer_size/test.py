#!/usr/bin/env python3

'''Test for IXFR from Knot to Knot'''

from dnstest.test import Test

t = Test()

master1 = t.server("knot")
master2 = t.server("knot")
slave = t.server("knot")
zone = t.zone("example.com.", storage=".")
slave.zone_size_limit = 230
t.link(zone, master1, slave, ixfr=True)
t.link(zone, master2, slave, ixfr=True)

t.start()

# Wait for zones.
serial = master1.zone_wait(zone)
slave.zone_wait(zone)

# Update master file with the record (new SOA serial).
master1.update_zonefile(zone, version=2)
master1.reload()

# Wait for zones and compare them.
master1.zone_wait(zone, serial)
t.sleep(10)

master2.update_zonefile(zone, version=1)  # smaller zone
master2.reload()

slave.zone_wait(zone, serial)

resp = slave.dig("test.example.com.", "TXT")

resp.check("passed")

#t.xfr_diff(master, slave, zone)

t.end()
