#!/usr/bin/env python3

'''Test of zone-in-journal: AXFR & IXFR to zonefile-less slave'''

from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")

zone = t.zone("example.com.")

t.link(zone, master, slave, journal_content="all")
slave.zonefile_sync = "-1"

t.start()

master.zone_wait(zone)
slave.zone_wait(zone)

# Check if bootstrapped and unflushed zone is accessible without master available.

master.stop()
slave.stop()
t.sleep(2)
slave.start()
slave.zone_wait(zone)

resp = slave.dig("mail.example.com.", "A")
resp.check(rcode="NOERROR", rdata="192.0.2.3")

resp = slave.dig("node.example.com.", "A")
resp.check(rcode="NXDOMAIN", nordata="1.2.3.4")

# Update the master zone and wait for updated slave.

master.start()
serial = master.zone_wait(zone)

up = master.update(zone)
up.add("node.example.com.", 3600, "A", "1.2.3.5")
up.send("NOERROR")

slave.zone_wait(zone, serial)

# Check if the zone with updates is accessible if not flushed and master not available.

master.stop()
slave.stop()
t.sleep(2)
slave.start()
slave.zone_wait(zone)

resp = slave.dig("mail.example.com.", "A")
resp.check(rcode="NOERROR", rdata="192.0.2.3")

resp = slave.dig("node.example.com.", "A")
resp.check(rcode="NOERROR", rdata="1.2.3.5")

t.end()
