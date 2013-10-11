#!/usr/bin/env python3

'''Test for header flags in response'''

import dnstest

t = dnstest.DnsTest()

knot = t.server("knot")
bind = t.server("bind")
zone = t.zone("flags.")

t.link(zone, knot)
t.link(zone, bind)

t.start()

# RD flag preservation.
resp = knot.dig("flags", "NS", recursion=True)
resp.check(flags="QR AA RD", noflags="TC RA AD CD")
resp.cmp(bind)

# NS record for delegated subdomain (not authoritative).
resp = knot.dig("sub.flags", "NS")
resp.check(flags="QR", noflags="AA TC RD RA AD CD")
resp.cmp(bind)

# Glue record for delegated subdomain (not authoritative).
resp = knot.dig("ns.sub.flags", "A")
resp.check(flags="QR", noflags="AA TC RD RA AD CD")
resp.cmp(bind)

# Check maximal UDP payload which fits into a response message.
resp = knot.dig("512resp.flags", "TXT", udp=True)
resp.check(flags="QR AA", noflags="TC RD RA AD CD")
resp.cmp(bind, flags=False) # Bind returns TC compared to Knot!

# TC bit - UDP.
resp = knot.dig("513resp.flags", "TXT", udp=True)
resp.check(flags="QR AA TC", noflags="RD RA AD CD")
resp.cmp(bind, authority=False) # Knot puts SOA compared to Bind!

# No TC bit - TCP.
resp = knot.dig("513resp.flags", "TXT", udp=False)
resp.check(flags="QR AA", noflags="TC RD RA AD CD")
resp.cmp(bind)

t.end()
