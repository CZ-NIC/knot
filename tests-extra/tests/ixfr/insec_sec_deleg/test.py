#!/usr/bin/env python3

'''Test insecure<->secure delegation transitions with NSEC3PARAM changes.'''

import random
from dnstest.test import Test

t = Test()

master = t.server("knot")
zones = t.zone("example.")

t.link(zones, master)

master.dnssec(zones[0]).enable = True
master.dnssec(zones[0]).nsec3 = True
master.dnssec(zones[0]).nsec3_opt_out = True
master.dnssec(zones[0]).nsec3_iters = 1

t.start()

master.zones_wait(zones)

master.dnssec(zones[0]).nsec3_iters = 2
master.gen_confile()
master.reload()
t.sleep(8)

up = master.update(zones)
up.add("b.example.", 3600, "DS", "57855 5 1 B6DCD485719ADCA18E5F3D48A2331627FDD3636B")
up.send()
t.sleep(4)

resp = master.dig("b.example.", "NS", dnssec=True)
resp.check_count(0, rtype="NSEC3", section="authority")

if random.random() < 0.5:
    master.dnssec(zones[0]).nsec3_iters = 3
    master.gen_confile()
    master.reload()
    t.sleep(6)

up = master.update(zones)
up.delete("a.example.", "DS")
up.send()
t.sleep(4)

resp = master.dig("a.example.", "NS", dnssec=True)
if resp.count("NSEC3", section="authority") < 1:
    resp.check_count(1, rtype="NSEC3", section="authority") # correct is 1 or 2

t.end()
