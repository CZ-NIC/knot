#!/usr/bin/env python3

'''Test for knotc zone-notify'''

from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")

zone = t.zone("notify.", storage=".")

t.link(zone, master, slave)

t.start()

master.zone_wait(zone)
slave.zone_wait(zone)

slave.stop()

master.update_zonefile(zone, version=1) # notify doesn't succeed while slave is offline
master.reload()

master.zone_wait(zone)

slave.start() # slave starts with older version of zone and doesn't attempt refersh since it's in timers

slave.zone_wait(zone)

resp = slave.dig("node.notify.", "A")
resp.check(rcode="NXDOMAIN")

master.ctl("zone-notify")

t.sleep(2)

resp = slave.dig("node.notify.", "A")
resp.check(rcode="NOERROR", rdata="1.2.3.4")

t.end()
