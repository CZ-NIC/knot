#!/usr/bin/env python3

'''geoip module functionality test'''

import dns.exception
import dns.message
import dns.query
import dns.edns
import os
import time

from dnstest.test import Test
from dnstest.module import ModGeoip
from dnstest.utils import *

ecs_wire = bytearray(b'\xde\xad\xbe\xef\xfe\xeb\xda\xed')

ModGeoip.check()
mod_geoip = ModGeoip("geo.conf", "geodb", "db.mmdb", ["country/iso_code", "(id)city/geoname_id"])
mod_geoip.check()

t = Test(stress=False)

knot = t.server("knot")
zone = t.zone("example.com")

t.link(zone, knot)

t.start()

