#!/usr/bin/env python3

'''Test for NOTIFY: if serial is different, slave shall update, otherwise not'''

from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")

zone = t.zone("notify.", storage=".")

t.link(zone, master, slave)

t.start()

serial = master.zone_wait(zone)
slave.zone_wait(zone)

master.update_zonefile(zone, version=1)
master.reload()

serial = slave.zone_wait(zone, serial=serial, equal=False, greater=True)

resp = slave.dig("node.notify.", "A")
resp.check(rcode="NOERROR", rdata="1.2.3.4")

slave.update_zonefile(zone, version=2)
slave.reload()

master.update_zonefile(zone, version=3)
master.reload()
# master now sends NOTIFY with SOA=2010111203 which shall slave ignore
t.sleep(2)

resp = slave.dig("nonode.notify.", "A")
resp.check(rcode="NXDOMAIN", nordata="1.2.3.5")

t.end()
