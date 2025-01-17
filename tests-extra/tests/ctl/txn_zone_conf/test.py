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

zonesock = master.ctl_sock_rnd()
confsock = master.ctl_sock_rnd()
zonesoc2 = master.ctl_sock_rnd()
confsoc2 = master.ctl_sock_rnd()

master.ctl("zone-begin " + ZONE, custom_parm=zonesock)

try:
    master.ctl("reload")
    set_err("allowed reload within zone txn")
except:
    pass

try:
    master.ctl("conf-begin", custom_parm=confsock)
    set_err("allowed conf-begin within zone txn")
except:
    pass

master.ctl("zone-set " + ZONE + " " + RNDNAME + " 3600 A 1.2.3.4", custom_parm=zonesock)
master.ctl("zone-commit " + ZONE, custom_parm=zonesock)

serials = master.zones_wait(zones, serials)
resp = master.dig(RNDNAME + "." + ZONE, "AAAA", dnssec=True)
resp.check()
resp.check_count(1, "NSEC", section="authority")
resp.check_count(0, "NSEC3", section="authority")

master.ctl("conf-begin", custom_parm=confsoc2)

try:
    master.ctl("zone-begin", custom_parm=zonesoc2)
    set_err("allowed zone-begin within conf txn")
except:
    pass

master.ctl("conf-set policy[" + ZONE + "].nsec3 on", custom_parm=confsoc2)
master.ctl("conf-commit", custom_parm=confsoc2)

serials = master.zones_wait(zones, serials)
resp = master.dig(RNDNAME + "." + ZONE, "AAAA", dnssec=True)
resp.check()
resp.check_count(0, "NSEC", section="authority")
resp.check_count(1, "NSEC3", section="authority")

t.end()
