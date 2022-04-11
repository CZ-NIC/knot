#!/usr/bin/env python3

'''Test that a defective zone is loaded and transfered with soft semantic checks.'''

from dnstest.test import Test
import dnstest.utils

t = Test()

master = t.server("knot")
slave = t.server("knot")

zone = t.zone("example.com.", storage=".")

t.link(zone, master, slave, ixfr=True)

master.semantic_check = "soft"
slave.semantic_check = "soft"

t.start()

serial_init = master.zones_wait(zone)
slave.zones_wait(zone)
t.xfr_diff(master, slave, zone)

master.update_zonefile(zone[0], version=1)
master.reload()

master.zones_wait(zone, serial_init)
slave.zones_wait(zone, serial_init)
t.xfr_diff(master, slave, zone, serial_init)

master.update_zonefile(zone[0], version=2)
master.reload()

for i in range(5): # Cannot use zones_wait() - SOA query!
    resp = slave.dig("txt.example.com", "TXT")
    if resp.rcode() == "NOERROR":
        break
    t.sleep(1)

t.xfr_diff(master, slave, zone)

t.end()
