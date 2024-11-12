#!/usr/bin/env python3

''''''

from dnstest.test import Test

t = Test()

master = t.server("knot")
zone = t.zone("test.", storage=".")

t.link(zone, master)

master.dnssec(zone).enable = True
master.dnssec(zone).nsec3 = True
master.dnssec(zone).nsec3_opt_out = True

t.start()

master.zone_wait(zone)

resp = master.dig("psy\\000cho.test.", "A", dnssec=True)

t.end()
