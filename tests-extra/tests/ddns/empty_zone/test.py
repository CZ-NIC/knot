#!/usr/bin/env python3

'''Empty zone initialization via DDNS, including DDNS forwarding'''

from dnstest.utils import *
from dnstest.test import Test
import random

t = Test(tls=True, quic=True)

master = t.server("knot")
slave = t.server("knot")

ZONE = "example.com."
zone = t.zone(ZONE, exists=False)
t.link(zone, master, slave, ddns=True)

if random.choice([False, True]):
    master.dnssec(zone).enable = True

if random.choice([False, True]):
    master.zones[ZONE].journal_content = "all"

if random.choice([False, True]):
    master.zonemd_generate = "zonemd-sha512"
    slave.zonemd_verify = True

t.start()

# Check the zone is empty
t.sleep(1)
resp = master.dig(ZONE, "SOA")
resp.check(rcode="SERVFAIL")

# Initial update without SOA
up = slave.update(zone)
up.add(ZONE, 3600, "TXT", "test")
up.send("SERVFAIL")

# Correct initial update with SOA
up = slave.update(zone)
up.add(ZONE, 3600, "SOA", "ns hostmaster 1 2m 5m 1w 5m")
up.send("NOERROR")

# Check the slave has the initialized zone
slave.zones_wait(zone)
resp = slave.dig(ZONE, "SOA")
resp.check(rcode="NOERROR")

t.end()
