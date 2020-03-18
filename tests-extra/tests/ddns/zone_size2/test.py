#!/usr/bin/env python3

'''Test of proper handling of error state at zone_update_commit (e.g. EZONESIZE).'''

from dnstest.test import Test
from dnstest.utils import *
import random

t = Test()

master = t.server("knot")
zone = t.zone("example.com.")
master.zone_size_limit = 5000

t.link(zone, master, ddns=True)
t.start()

master.zones_wait(zone)

# Step 1. Make zone_update_commit fail with EZONESIZE.

rc = "NOERROR"
deleg = ""
glue = ""
while rc == "NOERROR":
    deleg = "deleg%d.example.com." % random.randint(1, 100)
    glue = "glue%d.example.com." % random.randint(1, 10000)
    up = master.update(zone)
    up.add(deleg, 3600, "NS", glue)
    up.send(None)
    rc = up.rc
compare(rc, "REFUSED", "UPDATE RCODE")

next_step = random.choice([2, 3])

# Step 2. Check possibly dead pointer in additionals_tree (server would crash).

if next_step == 2:
    master.zone_size_limit = 10000
    master.gen_confile()
    master.reload()

    up = master.update(zone)
    up.add(glue, 3600, "A", "1.2.3.4")
    up.send("NOERROR")

# Step 3. Check that the changeset from failed update is not in journal.

if next_step == 3:
    resp = master.dig("example.com.", "SOA")
    soa1 = resp.soa_serial()

    master.stop()
    master.zone_size_limit = 10000
    master.gen_confile()
    master.start() # let the changesets from journal apply
    master.zones_wait(zone)

    resp = master.dig("example.com.", "SOA")
    soa2 = resp.soa_serial()

    compare(str(soa2), str(soa1), "JOURNAL SOA SERIAL")

t.end()
