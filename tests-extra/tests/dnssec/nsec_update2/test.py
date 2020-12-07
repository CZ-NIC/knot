#!/usr/bin/env python3

'''Test for specific issue that one of two NSECs did not disappear when changed to NONAUTH.'''

from dnstest.utils import *
from dnstest.test import Test

def verify(server, zone):
    server.flush()
    t.sleep(1)
    server.zone_verify(zone)

t = Test()

master = t.server("bind")
slave  = t.server("knot")

zone = t.zone("ripe.net.", storage=".")

t.link(zone, master, slave, ddns=True)

slave.dnssec(zone).enable = True
slave.dnssec(zone).nsec3 = False

t.start()

serial = slave.zone_wait(zone)

up = master.update(zone)
up.add("ad1.auth.ripe.net.",      86400, "A",    "193.0.4.66")
up.add("ad2.auth.ripe.net.",      86400, "A",    "193.0.4.67")
up.add("reth0-10.fw-2.ripe.net.", 86400, "A",    "193.0.4.65")
up.add("ad1.auth.ripe.net.",      86400, "AAAA", "2001:67c:2e8:10::c100:442")
up.add("ad2.auth.ripe.net.",      86400, "AAAA", "2001:67c:2e8:10::c100:442")
up.add("reth0-10.fw-2.ripe.net.", 86400, "AAAA", "2001:67c:2e8:10::1")
up.send()

serial = slave.zone_wait(zone, serial)
verify(slave, zone)

up = master.update(zone)
up.add("auth.ripe.net.",          86400, "NS", "ad1.auth.ripe.net.")
up.add("auth.ripe.net.",          86400, "NS", "ad2.auth.ripe.net.")
up.send()

serial = slave.zone_wait(zone, serial)
verify(slave, zone)

t.end()
