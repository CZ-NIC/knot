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

slave.ctl("zone-freeze", wait=True)

master1.zones[ZONE].zfile.update_soa(serial + 1)
master1.ctl("zone-reload", wait=True) # master1 is updated SOA by 1, sends NOTIFY
t.sleep(2)

master2.zones[ZONE].zfile.update_soa(serial - 1)
master2.ctl("zone-reload", wait=True) # master2 is updated SOA by -1, also sends NOTIFY
t.sleep(2)

slave.ctl("zone-thaw")

slave.zone_wait(zone, serial) # in case of failure: slave only tries master2 as the last one sending NOTIFY

t.end()
