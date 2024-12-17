#!/usr/bin/env python3

''' Check lowering zone maximal TTL by incremental update. '''

import os
import random

from dnstest.libknot import libknot
from dnstest.module import ModStats
from dnstest.test import Test
from dnstest.utils import *

def check_item(server, section, item, value, zone=None):
    try:
        ctl = libknot.control.KnotCtl()
        ctl.connect(os.path.join(server.dir, "knot.sock"))

        if zone:
            ctl.send_block(cmd="zone-stats", section=section, item=item, zone=zone)
        else:
            ctl.send_block(cmd="stats", section=section, item=item)

        stats = ctl.receive_stats()
    finally:
        ctl.send(libknot.control.KnotCtlType.END)
        ctl.close()

    if zone:
        stats = stats.get("zone").get(zone.lower())

    data = int(stats.get(section).get(item))

    compare(data, value, "%s.%s" % (section, item))

t = Test()

knot = t.server("knot")
zones = t.zone("example.com.", storage=".")

t.link(zones, knot)

knot.zonefile_load = "difference-no-serial"
knot.zones[zones[0].name].journal_content = "all"
knot.dnssec(zones).enable = True

t.start()
serials = knot.zones_wait(zones)

check_item(knot, "server", "zone-count", 1)
check_item(knot, "zone", "max-ttl", 3600, "example.com.")

knot.update_zonefile(zones[0], version=2)

if random.choice([False, True]):
    knot.ctl("zone-reload")
else:
    knot.stop()
    t.sleep(2)
    knot.start()

knot.zones_wait(zones, serials)

check_item(knot, "zone", "max-ttl", 1800, "example.com.")

t.end()
