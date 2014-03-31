#!/usr/bin/env python3

'''Test for IXFR query over UDP'''

from dnstest.test import Test

t = Test()

knot = t.server("knot")
bind = t.server("bind")
zone = t.zone("example.com.")

t.link(zone, knot)
t.link(zone, bind)

t.start()

# Wait for zone and get serial.
serial = bind.zones_wait(zone)
knot.zone_wait(zone)

# Query IXFR over UDP and compare responses.
t.xfr_diff(knot, bind, zone, serial, udp=True)

t.end()
