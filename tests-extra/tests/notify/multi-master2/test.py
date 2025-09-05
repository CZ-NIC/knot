#!/usr/bin/env python3

'''Test of not inhibiting received NOTIFY by another NOTIFY from outdated master.'''

from dnstest.test import Test

t = Test(address=4)

master1 = t.server("knot", address="127.0.0.11", via=True)
master2 = t.server("knot", address="127.0.0.12", via=True)
slave = t.server("knot")

zone = t.zone_rnd(1, records=300)
ZONE = zone[0].name

t.link(zone, master1, slave)
t.link(zone, master2, slave)

t.start()

serial = slave.zone_wait(zone)

# TEST 1: both masters send NOTIFY, but only the first one has higher serial than slave

slave.ctl("zone-freeze", wait=True)
slave.ctl("zone-flush", wait=True)

up = master1.update(zone)
up.add(ZONE, 3600, "SOA", "dns1 hostmaster %d 10800 3600 1209600 7200" % (serial + 2))
up.add("add1", 3600, "TXT", master1.name)
up.send()
t.sleep(2)

up = master2.update(zone)
up.add("add1", 3600, "TXT", master2.name)
up.send()
t.sleep(2)

slave.zones[ZONE].zfile.update_soa()
slave.ctl("zone-reload", wait=True)
serial = slave.zone_wait(zone, serial)
slave.ctl("zone-thaw")

# in case of failure: slave only tries master2 as the last one sending NOTIFY
serial = slave.zone_wait(zone, serial)
resp = slave.dig("add1." + ZONE, "TXT")
resp.check(rcode="NOERROR", rdata=master1.name, nordata=master2.name)

# TEST 2: master1 doesn't send NOTIFY, only master2 is attempted

slave.ctl("zone-freeze", wait=True)
slave.ctl("zone-flush", wait=True)

master1.disable_notify = True
master1.gen_confile()
master1.reload()

up = master2.update(zone)
up.add(ZONE, 3600, "SOA", "dns1 hostmaster %d 10800 3600 1209600 7200" % (serial + 1))
up.add("add2", 3600, "TXT", master2.name)
up.send()
t.sleep(2)

up = master1.update(zone)
up.add(ZONE, 3600, "SOA", "dns1 hostmaster %d 10800 3600 1209600 7200" % (serial + 2))
up.add("add2", 3600, "TXT", master1.name)
up.send()
t.sleep(2)

slave.zones[ZONE].zfile.update_soa()
slave.ctl("zone-reload", wait=True)
serial = slave.zone_wait(zone, serial)
slave.ctl("zone-thaw")

t.sleep(5)

# in case of failure: slave also tries master1 as the last one with greatest (greater) serial
slave.zone_wait(zone, serial, equal=True, greater=False)
resp = slave.dig("add2." + ZONE, "TXT")
resp.check(rcode="NXDOMAIN")

t.end()
