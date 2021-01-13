#!/usr/bin/env python3

"""
Test of zone-in-journal dynamic configuration.
"""

from dnstest.utils import *
from dnstest.test import Test

t = Test()

knot = t.server("knot")
zone = t.zone("example.")
t.link(zone, knot)

t.start()
knot.zone_wait(zone)

knot.ctl("conf-begin")
knot.ctl("conf-set zone[%s].journal-content all" % zone[0].name)
knot.ctl("conf-commit")
t.sleep(2)

knot.stop()

knot.zones[zone[0].name].journal_content = "all"
knot.zonefile_load = "none"
knot.gen_confile()

knot.zones[zone[0].name].zfile.remove() # just to make sure

knot.start()
knot.zone_wait(zone)

t.end()
