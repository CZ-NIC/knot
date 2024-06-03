#!/usr/bin/env python3

'''Test denial of concurrent control zone and config transactions.'''

from dnstest.utils import *
from dnstest.test import Test

t = Test()

master = t.server("knot")
zones = t.zone_rnd(1, dnssec=False, records=40)
t.link(zones, master)
ZONE = zones[0].name
RNDNAME = "fiowjfoiwjeodijwojdw"

for z in zones:
    master.dnssec(z).enable = True

t.start()
serials = master.zones_wait(zones)

master.ctl("zone-begin " + ZONE)

try:
    master.ctl("reload")
    set_err("allowed reload within zone txn")
except:
    pass

try:
    master.ctl("conf-begin")
    set_err("allowed conf-begin within zone txn")
except:
    pass

master.ctl("zone-set " + ZONE + " " + RNDNAME + " 3600 A 1.2.3.4")
master.ctl("zone-commit " + ZONE)

serials = master.zones_wait(zones, serials)
resp = master.dig(RNDNAME + "." + ZONE, "AAAA", dnssec=True)
resp.check()
resp.check_count(1, "NSEC", section="authority")
resp.check_count(0, "NSEC3", section="authority")

master.ctl("conf-begin")

try:
    master.ctl("zone-begin")
    set_err("allowed zone-begin within conf txn")
except:
    pass

master.ctl("conf-set policy[" + ZONE + "].nsec3 on")
master.ctl("conf-commit")

serials = master.zones_wait(zones, serials)
resp = master.dig(RNDNAME + "." + ZONE, "AAAA", dnssec=True)
resp.check()
resp.check_count(0, "NSEC", section="authority")
resp.check_count(1, "NSEC3", section="authority")

t.end()
