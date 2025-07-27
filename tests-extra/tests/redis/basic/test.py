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

# SOA serial logic rotation
serials6 = serials5

for i in range(5):
    if i == 3:
        slave.ctl("zone-freeze", wait=True)

    for z in zones:
        if i == 4:
            serials6[z.name] += 1
        else:
            serials6[z.name] += (1 << 30)
        serials6[z.name] %= (1 << 32)
        up = master.update(z)
        up.add(z.name, 3600, "SOA", "dns1 hostmaster %d 10800 3600 1209600 7200" % (serials6[z.name]))
        up.add("loop", 3600, "AAAA", "1::%d" % i)
        up.send()
    master.zones_wait(zones, serials6, equal=True)

slave.ctl("zone-thaw")
slave.zones_wait(zones, serials6, equal=True)
t.xfr_diff(master, slave, zones)
resp = slave.dig("loop." + zones[0].name, "AAAA")
resp.check(rcode="NOERROR", rdata="1::1")
resp.check(rcode="NOERROR", rdata="1::4")
resp.check_count(5, "AAAA")

t.end()
