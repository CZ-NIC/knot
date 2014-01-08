#!/usr/bin/env python3

'''Test for EDNS0 UDP payload size'''

from dnstest.test import Test

t = Test()

knot = t.server("knot")
bind = t.server("bind")
zone = t.zone("flags.")

t.link(zone, knot)
t.link(zone, bind)

t.start()

# TC - TXT record doesn't fit into UDP message.
resp = knot.dig("513resp.flags", "TXT", udp=True)
resp.check(flags="TC")
resp.cmp(bind, authority=False) # Knot puts SOA compared to Bind!

# no TC - UDP message is extended using EDNS0/payload.
resp = knot.dig("513resp.flags", "TXT", udp=True, bufsize=600)
resp.check(noflags="TC")
resp.cmp(bind)

# no TC - UDP message is extended using EDNS0/payload just for answer.
resp = knot.dig("513resp.flags", "TXT", udp=True, bufsize=524)
resp.check(noflags="TC")

t.end()
