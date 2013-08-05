#!/usr/bin/env python3

import os, sys
test_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(test_dir + "/../../tools")
from dnstest import *

################################################################################

t = DnsTest(test_dir, sys.argv[1])

master1 = t.server("knot", nsid="nsid", ident=True, version="Knot XXX")
master2 = t.server("knot", ident="ahoj")
slave = t.server("knot", ident="0xabcd")

#z1 = t.zone_rnd(10)

z1 = t.zone("example.com.", "example.com.zone")
z2 = t.zone("example2.com.", "example2.com.zone")

t.link(z1, master1, slave, ddns=True)
t.link(z2, master2, slave)

t.start()

t.stop()

'''
t.link(z2, master, slave2)
t.link(z2, master, slave1)


t.dig()

t.stop()

t.end()
'''


