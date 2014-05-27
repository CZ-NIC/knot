#!/usr/bin/env python3

'''Test for loading of NSEC records with upper-case letters in rdata.'''

from dnstest.test import Test

t = Test()

knot = t.server("knot")
bind = t.server("bind")
zone = t.zone("rdatacase.", "rdatacase.zone.signed", storage=".")

t.link(zone, knot)
t.link(zone, bind)

t.start()

knot.zones_wait(zone)
bind.zones_wait(zone)
t.xfr_diff(knot, bind, zone)

t.end()
