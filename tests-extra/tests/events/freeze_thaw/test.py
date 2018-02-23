#!/usr/bin/env python3

'''Test of freeze-thaw feature'''

from dnstest.test import Test

t = Test(tsig=False)

master = t.server("knot")
slave = t.server("knot")

zone = t.zone("example.", storage=".")
t.link(zone, master, slave)

t.start()

master.zone_wait(zone)
slave.zone_wait(zone)

slave.ctl("zone-freeze")

master.update_zonefile(zone, version=1)
master.reload()
master.zone_wait(zone, serial=2, equal=True)
t.sleep(1)

# check that slave freezed transfer after obtained notify
resp = slave.dig("added.example.", "A")
resp.check(rcode="NXDOMAIN", nordata="1.2.3.4")

slave.ctl("zone-refresh")

# check that slave transferred when invoked from ctl
slave.zone_wait(zone, serial=2, equal=True)
resp = slave.dig("added.example.", "A")
resp.check(rcode="NOERROR", rdata="1.2.3.4")

# check that update is refused
up = slave.update(zone)
up.add("noddns", 3600, "A", "1.2.3.6")
up.send("REFUSED")
t.sleep(2)
resp = slave.dig("noddns.example.", "A")
resp.check(rcode="NXDOMAIN", nordata="1.2.3.6")

master.update_zonefile(zone, version=2)
master.reload()
master.zone_wait(zone, serial=3, equal=True)
t.sleep(1)

slave.ctl("zone-thaw")

# check that slave retransfered immediately after thaw
slave.zone_wait(zone, serial=3, equal=True)
resp = slave.dig("more.example.", "A")
resp.check(rcode="NOERROR", rdata="1.2.3.5")

# check that update works now
up = slave.update(zone)
up.add("ddns", 3600, "A", "1.2.3.7")
up.send("NOERROR")
t.sleep(2)
resp = slave.dig("ddns.example.", "A")
resp.check(rcode="NOERROR", rdata="1.2.3.7")

t.stop()
