#!/usr/bin/env python3

from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")
zone = t.zone("example.com.", storage=".")

master.zonefile_sync = "-1"
slave.zonefile_sync = "0"

t.link(zone, master, slave, ixfr=True)

master.dnssec(zone).enable = True
master.dnssec(zone).nsec3 = True

t.start()

slave.zone_wait(zone)

master.update_zonefile(zone, version=1)
master.reload()

master.stop()
master.start()

t.sleep(2)

slave.zone_verify(zone, ldns_check=True)

t.end()
