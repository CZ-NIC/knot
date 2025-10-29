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

confsock = knot.ctl_sock_rnd()
knot.ctl("conf-begin", custom_parm=confsock)
knot.ctl("conf-set zone[%s].journal-content all" % zone[0].name, custom_parm=confsock)
knot.ctl("conf-commit", custom_parm=confsock)
t.sleep(2)

knot.stop()

knot.conf_zone(zone).journal_content = "all"
knot.conf_zone(zone).zonefile_load = "none"
knot.gen_confile()

knot.zones[zone[0].name].zfile.remove() # just to make sure

knot.start()
knot.zone_wait(zone)

t.end()
