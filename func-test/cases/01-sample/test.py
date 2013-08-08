#!/usr/bin/env python3

import os, sys
test_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(test_dir + "/../../tools")
from dnstest import *

################################################################################

t = DnsTest(test_dir, sys.argv[1])

master1 = t.server("knot", nsid="nsid", ident=True, version="Knot XXX")
master2 = t.server("bind", ident="ahoj", version="xx")
slave = t.server("bind", nsid="0xabcd")

z1 = t.zone("example.com.", "example.com.zone")
z2 = t.zone("example2.com.", "example2.com.zone")
z3 = t.zone_rnd(5)


t.link(z1, master1, slave, ddns=True)
t.link(z2, master2, slave)
t.link(z3, master2, slave)
t.link(z3, slave, master1)

t.start()

t.stop()
