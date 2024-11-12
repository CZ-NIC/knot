#!/usr/bin/env python3

'''Test for zero byte in a QNAME label.'''

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
resp.check(rcode="NXDOMAIN")

resp = master.dig("psy\\000cho\\000nxd.test.", "A", dnssec=True)
resp.check(rcode="NXDOMAIN")

resp = master.dig("exis\\000ing.test.", "A", dnssec=True)
resp.check(rcode="NOERROR", rdata="1.2.3.4")

resp = master.dig("ing.exis.test.", "A", dnssec=True)
resp.check(rcode="NXDOMAIN", nordata="1.2.3.4")

t.end()
