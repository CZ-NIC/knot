#!/usr/bin/env python3

'''Test for EDNS0 UDP payload size'''

import dnstest

t = dnstest.DnsTest()

server = t.server("knot")
zone = t.zone("flags.")

t.link(zone, server)

t.start()

# TC - TXT record doesn't fit into UDP message.
resp = server.dig("text.flags", "TXT", udp=True)
resp.check(flags="TC")

# no TC - UDP message is extended using EDNS0/payload.
resp = server.dig("text.flags", "TXT", udp=True, bufsize=700)
resp.check(noflags="TC")

t.stop()
