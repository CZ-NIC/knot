#!/usr/bin/env python3

'''Test for automatic ACL'''

import random

from dnstest.utils import *
from dnstest.test import Test
from dnstest.keys import Tsig

TSIG = Tsig() if random.choice([True, False]) else False
if TSIG:
    MASTER_AUTO = True
    SLAVE_AUTO = True
else:
    MASTER_AUTO = random.choice([True, False])
    SLAVE_AUTO = True if not MASTER_AUTO else random.choice([True, False])

check_log("TSIG %s, master_auto_ACL %s, slave_auto_ACL %s" % \
          (str(TSIG != False), str(MASTER_AUTO), str(SLAVE_AUTO)))

t = Test(tsig=(TSIG != False))

master = t.server("knot", tsig=TSIG)
slave = t.server("knot", tsig=TSIG)
zones = t.zone("example.com.")

master.auto_acl = MASTER_AUTO
slave.auto_acl = SLAVE_AUTO

t.link(zones, master, slave, ixfr=True)

t.start()

# Wait for AXFR to slave server.
serials_init = master.zones_wait(zones)
slave.zones_wait(zones)

serials_prev = serials_init
for i in range(2):
    master.update_zonefile(zones[0], random=True)
    master.reload()

    serials = master.zones_wait(zones, serials_prev)
    slave.zones_wait(zones, serials_prev)
    serials_prev = serials

t.end()
