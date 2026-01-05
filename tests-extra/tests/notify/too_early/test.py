#!/usr/bin/env python3

'''Test that NOTIFY is not sent before server is answering (on XFR).'''

from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")

zones = t.zone_rnd(1, records=1200, names=["zzzzzzzzz."]) + t.zone("example.")

t.link(zones, master, slave)

master.dnssec(zones[0]).enable = True
slave.conf_zone(zones).retry_min_interval = 300

t.generate_conf()
slave.start()
master.start()

serials = master.zones_wait(zones)
slave.zones_wait(zones)

t.end()
