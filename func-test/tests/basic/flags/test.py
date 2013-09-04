#!/usr/bin/env python3

'''Test for header flags in response'''

import dnstest

t = dnstest.DnsTest()

knot = t.server("knot")
zone = t.zone("flags.")

t.link(zone, knot)

t.start()

# RD flag preservation.
resp = knot.dig("flags", "NS", recursion=True)
resp.check(flags="QR AA RD", noflags="TC RA AD CD")

# NS record for delegated subdomain (not authoritative).
resp = knot.dig("sub.flags", "NS")
resp.check(flags="QR", noflags="AA TC RD RA AD CD")

# Glue record for delegated subdomain (not authoritative).
resp = knot.dig("ns.sub.flags", "A")
resp.check(flags="QR", noflags="AA TC RD RA AD CD")

# TC bit - UDP.
resp = knot.dig("text.flags", "TXT", udp=True)
resp.check(flags="QR AA TC", noflags="RD RA AD CD")

# No TC bit - TCP.
resp = knot.dig("text.flags", "TXT", udp=False)
resp.check(flags="QR AA", noflags="TC RD RA AD CD")

t.stop()
