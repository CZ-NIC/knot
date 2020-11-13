#!/usr/bin/env python3

"""
Test of zone force reload.
"""

from dnstest.utils import *
from dnstest.test import Test

t = Test()

knot = t.server("knot")
zone = t.zone_rnd(1, records=450)
t.link(zone, knot)
knot.dnssec(zone).enable = True

if knot.valgrind:
    knot.ctl_params_append = ["-t", "30"]

t.start()
serial = knot.zone_wait(zone)

knot.ctl("   zone-sign   %s" % zone[0].name, wait=False)
knot.ctl("-f zone-reload %s" % zone[0].name, wait=True)

resp = knot.dig(zone[0].name, "SOA")
compare(resp.soa_serial(), serial + 1, "SOA serial")

t.end()
