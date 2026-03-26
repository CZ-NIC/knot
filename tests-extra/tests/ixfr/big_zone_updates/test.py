#!/usr/bin/env python3

'''Big zone with frequent updates.'''

from dnstest.test import Test

t = Test()

master = t.server("bind")
slave = t.server("knot")
zone = t.zone_rnd(1, records=16000, dnssec=False)

t.link(zone, master, slave, ixfr=True, ddns=True)

t.start()

slave.zones_wait(zone)

for i in range(10):
    up = master.update(zone)
    up.add("add%d" % i, 3600, "A", "1.2.3.%d" % (i % 100))
    up.send()
    t.sleep(0.5)

t.stop()
