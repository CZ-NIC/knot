#!/usr/bin/env python3

'''Test for EDNS0 UDP payload size'''

from dnstest.test import Test

t = Test()

knot = t.server("knot")
bind = t.server("bind")
zones = t.zone("flags.") + t.zone("example.", "example.zone.nsec", local=True)

t.link(zones, knot)
t.link(zones, bind)

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

# check if RRSIG not fitting in the AR causes truncation
resp = knot.dig("example", "SOA", udp=True, dnssec=True, bufsize=1400)
resp.check(noflags="TC")

t.end()
