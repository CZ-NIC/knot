#!/usr/bin/env python3

'''Test for empty rdata loading.'''

from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")
zone = t.zone("empty.", storage=".")

t.link(zone, master, slave)

t.start()

master.zones_wait(zone)
slave.zones_wait(zone)

slave.flush(zone)
t.sleep(1)

t.end()
