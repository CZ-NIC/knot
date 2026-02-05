#!/usr/bin/env python3

'''Test (not)storing diff to Redis based on circumstances.'''

import random
from dnstest.test import Test
from dnstest.utils import *

def check_soa(redis, zone_name, instance, expected):
    out = redis.cli("knot.zone.load", zone_name, str(instance))
    soa_rdata = out.splitlines()[3]
    soa_serial = soa_rdata.split()[2]
    compare(soa_serial, str(expected), "Redis SOA serial")

t = Test()

master = t.server("knot")

zone = t.zone("example.com.")
Z = zone[0].name

t.link(zone, master)

redis_master = t.backend("redis", tls=random.choice([True, False]))

master.db_out(zone, [redis_master], 1)
master.dnssec(zone).enable = True

t.start()

serial = master.zone_wait(zone)
check_soa(redis_master, Z, 1, serial)

ch1 = redis_master.cli("knot.upd.load", Z, "1", str(serial - 1))
if len(ch1) > 1:
    set_err("Non-empty zonefile-to-signed initial changeset.")

up = master.update(zone)
up.add("somestuff", 3600, "AAAA", "1::15")
up.send("NOERROR")
serial = master.zone_wait(zone, serial)
check_soa(redis_master, Z, 1, serial)

ch2 = redis_master.cli("knot.upd.load", Z, "1", str(serial - 1))
if "somestuff" not in ch2:
    set_err("Missing DDNS update changeset.")

master.zones[Z].zfile.update_soa(serial = serial + 10)
master.ctl("zone-reload")
master.zone_wait(zone, serial + 10)
check_soa(redis_master, Z, 1, serial + 11)

ch3 = redis_master.cli("knot.upd.load", Z, "1", str(serial + 10))
if len(ch3) > 1:
    set_err("Non-empty zonefile-to-signed non-continuous changeset.")

ch4 = redis_master.cli("knot.upd.load", Z, "1", str(serial - 1))
if len(ch4) > 1:
    set_err("Remaining DDNS update changeset despite discontinuity.")

ch5 = redis_master.cli("knot.upd.load", Z, "1", str(serial))
if len(ch5) > 1:
    set_err("Non-empty different changeset.")

t.end()
