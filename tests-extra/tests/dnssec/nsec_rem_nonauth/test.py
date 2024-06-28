#!/usr/bin/env python3

'''Test removing orphan NSEC from non-authoritative node.'''

from dnstest.test import Test
from dnstest.utils import *

t = Test()

server = t.server("knot")
zone = t.zone("example.", storage=".")

t.link(zone, server)

for z in zone:
    server.dnssec(z).enable = True

t.start()

server.zone_wait(zone)
server.ctl("zone-flush", wait=True)
server.zone_verify(zone)

t.end()
