#!/usr/bin/env python3

"""
Test of autogenerating reverse zone.
"""

from dnstest.utils import *
from dnstest.test import Test

t = Test()

knot = t.server("knot")
zones = t.zone("example.com.", storage=".") + \
        t.zone("2.0.192.in-addr.arpa.", storage=".") + \
        t.zone("0.8.b.d.1.0.0.2.ip6.arpa.", storage=".")
t.link(zones, knot)

knot.zones[zones[1].name].reverse_from = zones[0]
knot.zones[zones[2].name].reverse_from = zones[0]

t.start()
t.sleep(5)

r = knot.dig("mail.0.8.b.d.1.0.0.2.ip6.arpa.", "A")
r.check(rcode="NOERROR", rdata="192.0.2.3")

r = knot.dig("3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.1.0.0.2.ip6.arpa.", "PTR")
r.check(rcode="NOERROR", rdata="mail.example.com.")

r = knot.dig("2.2.0.192.in-addr.arpa.", "PTR")
r.check(rcode="NOERROR", rdata="dns2.example.com.")

r = knot.dig("5.2.0.192.in-addr.arpa.", "PTR")
r.check(rcode="NXDOMAIN", nordata="added.example.com.")

knot.update_zonefile(zones[0], version=1)
knot.ctl("zone-reload %s" % zones[0].name)
t.sleep(5)

r = knot.dig("5.2.0.192.in-addr.arpa.", "PTR")
r.check(rcode="NOERROR", rdata="added.example.com.")

r = knot.dig("3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.1.0.0.2.ip6.arpa.", "PTR")
r.check(rcode="NXDOMAIN", nordata="mail.example.com.")

r = knot.dig("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.1.0.0.2.ip6.arpa.", "PTR")
r.check(rcode="NOERROR", rdata="dns1.example.com.")

knot.ctl("zone-reload %s" % zones[2].name)
t.sleep(5)

r = knot.dig("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.1.0.0.2.ip6.arpa.", "PTR")
r.check(rcode="NOERROR", rdata="dns1.example.com.")

knot.zones.pop(zones[1].name)
knot.gen_confile()
knot.reload()
t.sleep(5)

knot.update_zonefile(zones[0], version=2)
knot.ctl("zone-reload %s" % zones[0].name)
t.sleep(5)

r = knot.dig("2.2.0.192.in-addr.arpa.", "PTR")
r.check(rcode="REFUSED", nordata="dns2.example.com.")

r = knot.dig("5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.1.0.0.2.ip6.arpa.", "PTR")
r.check(rcode="NOERROR", rdata="added2.example.com.")

knot.zones.pop(zones[0].name)
knot.gen_confile()
knot.reload()
t.sleep(5)

r = knot.dig("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.1.0.0.2.ip6.arpa.", "PTR")
r.check(rcode="NOERROR", rdata="dns1.example.com.")

knot.ctl("zone-reload %s" % zones[2].name)
t.sleep(5)

r = knot.dig("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.1.0.0.2.ip6.arpa.", "PTR")
r.check(rcode="NXDOMAIN", nordata="dns1.example.com.")

t.end()
