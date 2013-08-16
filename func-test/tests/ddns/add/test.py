#!/usr/bin/env python3

import dnstest

t = dnstest.DnsTest()

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

t.end()
