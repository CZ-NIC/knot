#!/usr/bin/env python3

'''Test master-slave-like replication using Redis database.'''

from dnstest.test import Test

t = Test(redis=True)

master = t.server("knot")
slave = t.server("knot")

zones = t.zone("example.com.")

t.link(zones, master)
t.link(zones, slave)

master.zonefile_sync = "0"

for z in zones:
    master.zones[z.name].redis_out = "1"
    slave.zones[z.name].redis_in = "1"
    slave.zones[z.name].zfile.remove()

t.start()

master.zones_wait(zones)

master.ctl("zone-flush", wait=True)
#slave.ctl("zone-reload")

serials = slave.zones_wait(zones)
t.xfr_diff(master, slave, zones)

for z in zones:
    up = master.update(z)
    up.add("suppnot1", 3600, "A", "1.2.3.4")
    up.send()

t.sleep(2)
master.ctl("zone-flush", wait=True)
#slave.ctl("zone-reload")

slave.zones_wait(zones, serials)
t.xfr_diff(master, slave, zones)

t.end()
