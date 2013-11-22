#!/usr/bin/env python3

'''NSEC3 test based on RFC-4035 example.'''

from dnstest.test import Test

t = Test()

knot = t.server("knot")
knot.DIG_TIMEOUT = 2
bind = t.server("bind")
zone = t.zone("example.", "example.zone.nsec3")

t.link(zone, knot)
t.link(zone, bind)

t.start()

# B1. Answer.
resp = knot.dig("x.w.example", "MX", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA", eflags="DO")
resp.cmp(bind)

# B2. Name Error.
resp = knot.dig("ml.example", "A", dnssec=True)
resp.check(rcode="NXDOMAIN", flags="QR AA", eflags="DO")
resp.cmp(bind)

# B3. No Data Error.
resp = knot.dig("ns1.example", "MX", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA", eflags="DO")
resp.cmp(bind)

# B4. Referral to Signed Zone.
resp = knot.dig("mc.a.example", "MX", dnssec=True)
resp.check(rcode="NOERROR", flags="QR", noflags="AA", eflags="DO")
resp.cmp(bind)

# B5. Referral to Unsigned Zone.
resp = knot.dig("mc.b.example", "MX", dnssec=True)
resp.check(rcode="NOERROR", flags="QR", noflags="AA", eflags="DO")
resp.cmp(bind)

# B6. Wildcard Expansion.
resp = knot.dig("a.z.w.example", "MX", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA", eflags="DO")
resp.cmp(bind)

# B7. Wildcard No Data Error.
resp = knot.dig("a.z.w.example", "AAAA", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA", eflags="DO")
resp.cmp(bind)

# B8. DS Child Zone No Data Error.
resp = knot.dig("example", "DS", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA", eflags="DO")
resp.cmp(bind)

t.end()
