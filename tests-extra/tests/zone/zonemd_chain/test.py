#!/usr/bin/env python3

"""
Test of bump-in-the-wire signer receiving ZONEMD in unsigned version of the zone.
"""

from dnstest.utils import *
from dnstest.test import Test
import random
import threading
import time

t = Test()

master = t.server("knot")
signer = t.server("knot")
slave = t.server("knot")
ZONE = "example."
zones = t.zone(ZONE)

t.link(zones, master, signer)
t.link(zones, signer, slave)

master.conf_zone(zones).zonemd_generate = "zonemd-sha384"
signer.conf_zone(zones).zonemd_verify = True

signer.dnssec(zones).enable = True
signer.conf_zone(zones).zonemd_generate = random.choice(["zonemd-sha384", "zonemd-sha512"])

slave.conf_zone(zones).dnssec_validation = True
slave.conf_zone(zones).zonemd_verify = True

t.start()
serials = slave.zones_wait(zones)

master.random_ddns(zones, allow_empty=False)
serials = slave.zones_wait(zones, serials)

signer.ctl("zone-freeze", wait=True)
master.random_ddns(zones, allow_empty=False)
master.random_ddns(zones, allow_empty=False)
signer.ctl("zone-thaw")
serials = slave.zones_wait(zones, serials)

t.end()
