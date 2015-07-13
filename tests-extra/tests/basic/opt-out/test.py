#!/usr/bin/env python3

'''NSEC3 opt-out flag test based on RFC-5155 example.'''

from dnstest.test import Test

t = Test()

knot = t.server("knot")
knot.DIG_TIMEOUT = 2
bind = t.server("bind")
zone = t.zone("example.", storage=".")

t.link(zone, knot)
t.link(zone, bind)

t.start()

# B1. Name Error.
resp = knot.dig("a.c.x.w.example.", "A", dnssec=True)
resp.check(rcode="NXDOMAIN", flags="QR AA", eflags="DO")
resp.cmp(bind)

# B2. No Data Error.
resp = knot.dig("ns1.example.", "MX", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA", eflags="DO")
resp.cmp(bind)

# B2.1. No Data Error, Empty Non-Terminal.
resp = knot.dig("y.w.example.", "A", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA", eflags="DO")
resp.cmp(bind)

# B3. Referral to an Opt-Out Unsigned Zone.
resp = knot.dig("mc.c.example.", "MX", dnssec=True)
resp.check(rcode="NOERROR", flags="QR", noflags="AA", eflags="DO")
resp.cmp(bind, additional=True)

# B4. Wildcard Expansion.
resp = knot.dig("a.z.w.example.", "MX", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA", eflags="DO")
resp.cmp(bind)

# B5. Wildcard No Data Error.
resp = knot.dig("a.z.w.example.", "AAAA", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA", eflags="DO")
resp.cmp(bind)

# B6. DS Child Zone No Data Error.
resp = knot.dig("example.", "DS", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA", eflags="DO")
resp.cmp(bind)

t.end()
