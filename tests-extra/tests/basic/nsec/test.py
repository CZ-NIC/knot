#!/usr/bin/env python3

'''NSEC test based on RFC-4035 example.'''

from dnstest.test import Test

t = Test()

knot = t.server("knot")
knot.DIG_TIMEOUT = 2
bind = t.server("bind")
zone = t.zone("example.", "example.zone.nsec", storage=".")

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
resp.cmp(bind, additional=True)

# B5. Referral to Unsigned Zone.
resp = knot.dig("mc.b.example", "MX", dnssec=True)
resp.check(rcode="NOERROR", flags="QR", noflags="AA", eflags="DO")
resp.cmp(bind, additional=True)

# B6. Wildcard Expansion.
resp = knot.dig("a.z.w.example", "MX", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA", eflags="DO")
resp.cmp(bind)

# B7. Wildcard No Data Error.
resp = knot.dig("a.z.w.example", "AAAA", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA", eflags="DO")
resp.cmp(bind)

# No wildcard match because empty non-terminal (y.w.example) exists.
resp = knot.dig("a.y.w.example", "AAAA", dnssec=True)
resp.check(rcode="NXDOMAIN", flags="QR AA", eflags="DO")
resp.cmp(bind)

# Wildcard Expansion to apex
resp = knot.dig("a.to-apex.example", "SOA", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA", eflags="DO")
resp.cmp(bind)

# Wildcard Expansion to apex (no data)
resp = knot.dig("a.to-apex.example", "TXT", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA", eflags="DO")
resp.cmp(bind)

# Wildcard Expansion to non-existent name
resp = knot.dig("a.to-nxdomain.example", "A", dnssec=True)
resp.check(rcode="NXDOMAIN", flags="QR AA", eflags="DO")
resp.cmp(bind)

# Wildcard Expansion below delegation point
resp = knot.dig("a.a.example", "A", dnssec=True)
resp.check(rcode="NOERROR", flags="QR", eflags="DO")
resp.cmp(bind, additional=True)

# Wildcard Expansion below delegation point (no data)
resp = knot.dig("a.a.example", "AAAA", dnssec=True)
resp.check(rcode="NOERROR", flags="QR", eflags="DO")
resp.cmp(bind, additional=True)

# Direct wildcard query (positive)
resp = knot.dig("*.w.example", "MX", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA", eflags="DO")
resp.cmp(bind)

# Direct wildcard query (no data)
resp = knot.dig("*.w.example", "AAAA", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA", eflags="DO")
resp.cmp(bind)

# Direct wildcard query below delegation point (positive)
resp = knot.dig("*.a.example", "A", dnssec=True)
resp.check(rcode="NOERROR", flags="QR", eflags="DO")
resp.cmp(bind, additional=True)

# Direct wildcard query below delegation point (no data)
resp = knot.dig("*.a.example", "AAAA", dnssec=True)
resp.check(rcode="NOERROR", flags="QR", eflags="DO")
resp.cmp(bind, additional=True)

# B8. DS Child Zone No Data Error.
resp = knot.dig("example", "DS", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA", eflags="DO")
resp.cmp(bind)

# DS query at delegation
resp = knot.dig("a.example", "DS", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA", eflags="DO")
resp.cmp(bind)

# DS query at delegation (insecure)
resp = knot.dig("b.example", "DS", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA", eflags="DO")
resp.cmp(bind)

# Empty non-terminal
resp = knot.dig("y.w.example", "A", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA", eflags="DO")
resp.cmp(bind)

# Wildcard NSEC with delegation boundary (Knot specific).
resp = knot.dig("b.nsec-deleg.z.z.example", "A", dnssec=True)
resp.check(rcode="NXDOMAIN", flags="QR AA", eflags="DO")
resp.cmp(bind)

t.end()
