#!/usr/bin/env python3

"""
Check of multi-keystore operation.
"""

from dnstest.keystore import KnotPkcs11SoftHSM
from dnstest.utils import *
from dnstest.test import Test

t = Test()

server = t.server("knot")
zone = t.zone("catalog.") # has zero TTL => faster key rollovers
t.link(zone, server)

keys1 = KnotPkcs11SoftHSM("keys1", "knot", "1234", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so")

server.dnssec(zone).enable = True
server.dnssec(zone).propagation_delay = 1
server.dnssec(zone).keystore = [ keys1 ]

t.start()
serial = server.zone_wait(zone)

server.dnssec(zone).keystore = [ keys1 ]
server.gen_confile()
server.reload()
server.ctl("zone-key-rollover %s zsk" % zone[0].name)

serial += 2 # wait for three increments which is whole ZSK rollover
serial = server.zone_wait(zone, serial)

server.ctl("zone-sign %s" % zone[0].name, wait=True) # check that signing still works after restore
serial = server.zone_wait(zone, serial)

server.flush(zone[0], wait=True)
server.zone_verify(zone[0])

keys0ksk = KnotPkcs11SoftHSM("keys0ksk", "knotksk", "1234", ksk_only=True)

server.dnssec(zone).keystore = [ keys0ksk, keys1 ]
server.gen_confile()
server.reload()

server.ctl("zone-key-rollover %s ksk" % zone[0].name)
serial = server.zone_wait(zone, serial)

# server.ctl("zone-ksk-submitted %s" % zone[0].name)
# serial = server.zone_wait(zone, serial)

# server.ctl("zone-key-rollover %s zsk" % zone[0].name)
# serial += 2 # wait for three increments which is whole ZSK rollover
# serial = server.zone_wait(zone, serial)

t.end()
