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
signer.conf_zone(zones).zonemd_generate = "zonemd-sha384"

slave.conf_zone(zones).dnssec_validation = True
slave.conf_zone(zones).zonemd_verify = True

t.start()
serials = slave.zones_wait(zones)

master.random_ddns(zones, allow_empty=False)
t.sleep(4)
slave.zones_wait(zones, serials, equal=True, greater=False)
signer.ctl("zone-retransfer")
serials = slave.zones_wait(zones, serials)

signer.conf_zone(zones).zonemd_verify = False
signer.gen_confile()
signer.reload()

master.random_ddns(zones, allow_empty=False)
serials = slave.zones_wait(zones, serials)
if signer.log_search_count("fallback to AXFR ") > 0: # NOTE without the trailing space the message can appear for outgoing IXFR as well, which it actually should
    set_err("AXFR fallback")

t.end()
