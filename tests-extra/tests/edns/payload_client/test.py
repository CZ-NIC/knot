#!/usr/bin/env python3

'''Test for EDNS0 UDP payload size limiting on the client side'''

from dnstest.test import Test
import dnstest.keys

key = dnstest.keys.Tsig(name="key", alg="hmac-sha1", key="dmVyeWxvbmdrZXk=")

t = Test(tsig=key)

knot = t.server("knot")
bind = t.server("bind")
zone = t.zone("flags.")

t.link(zone, knot)
t.link(zone, bind)

t.start()

# TC - TXT record doesn't fit into UDP message (no TSIG).
resp = knot.dig("513resp.flags", "TXT", udp=True, tsig=False)
resp.check(flags="TC")
resp.cmp(bind, additional=True)

# no TC - UDP message is extended using EDNS0/payload (no TSIG).
resp = knot.dig("513resp.flags", "TXT", udp=True, bufsize=524, tsig=False)
resp.check(noflags="TC")
resp.cmp(bind, additional=True)

# TC - UDP message is extended using EDNS0/payload (with TSIG).
resp = knot.dig("513resp.flags", "TXT", udp=True, bufsize=524+61, tsig=key)
resp.check(flags="TC")
resp.cmp(bind, additional=True)

# no TC - UDP message is extended using EDNS0/payload (with TSIG).
resp = knot.dig("513resp.flags", "TXT", udp=True, bufsize=524+62, tsig=key)
resp.check(noflags="TC")
resp.cmp(bind, additional=True)

t.end()
