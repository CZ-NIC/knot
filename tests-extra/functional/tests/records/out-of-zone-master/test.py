#!/usr/bin/env python3

'''Test for dropping of out of zone records during reading of zone file'''

import dnstest

t = dnstest.DnsTest()

master = t.server("knot")
slave = t.server("bind")
zone = t.zone("out-of-zone.")

t.link(zone, master, slave)

t.start()

master.zones_wait(zone)
slave.zones_wait(zone)

t.xfr_diff(master, slave, zone)

t.end()
