#!/usr/bin/env python3

"""
Test of zone force reload and realod from indir.
"""

from dnstest.utils import *
from dnstest.test import Test
import dnstest.params

t = Test()

knot = t.server("knot")
zone = t.zone("example.com.", storage=".")
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

knot.ctl("zone-sign   %s" % zone[0].name, wait=False)
knot.ctl("zone-reload %s +indir %s" % (zone[0].name, dnstest.params.common_data_dir), wait=True)

resp = knot.dig(zone[0].name, "SOA")
compare(resp.soa_serial(), 2010111201 + 1, "SOA serial from indir")

t.end()
