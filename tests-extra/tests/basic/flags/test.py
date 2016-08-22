#!/usr/bin/env python3

'''Test for header flags in response'''

from dnstest.test import Test

t = Test()

knot = t.server("knot")
bind = t.server("bind")
zone = t.zone("flags.")

# Disable ANY over UDP
knot.disable_any = True

t.link(zone, knot)
t.link(zone, bind)

t.start()

# RD flag preservation.
resp = knot.dig("flags", "NS", flags="RD")
resp.check(flags="QR AA RD", noflags="TC RA AD CD Z")
resp.cmp(bind)

# CD flag preservation.
resp = knot.dig("flags", "NS", flags="CD")
resp.check(flags="QR AA CD", noflags="TC RA AD RD Z")
resp.cmp(bind)

# TC flag must be cleared
resp = knot.dig("flags", "NS", flags="TC")
resp.check(flags="QR AA", noflags="TC RA AD CD RD Z")
resp.cmp(bind)

# AD flag must be cleared
resp = knot.dig("flags", "NS", flags="AD")
resp.check(flags="QR AA", noflags="TC RA AD CD RD Z")
resp.cmp(bind)

# AA flag must be cleared
resp = knot.dig("sub.flags", "NS", flags="AA")
resp.check(flags="QR", noflags="AA TC RD RA AD CD Z")
resp.cmp(bind, additional=True)

# RA flag must be cleared
resp = knot.dig("flags", "NS", flags="RA")
resp.check(flags="QR AA", noflags="TC RA AD CD RD Z")
resp.cmp(bind)

# Z flag must be cleared
resp = knot.dig("flags", "NS", flags="Z")
resp.check(flags="QR AA", noflags="TC RA AD CD RD Z")
resp.cmp(bind)

# NS record for delegated subdomain (not authoritative).
resp = knot.dig("sub.flags", "NS")
resp.check(flags="QR", noflags="AA TC RD RA AD CD Z")
resp.cmp(bind, additional=True)

# Glue record for delegated subdomain (not authoritative).
resp = knot.dig("ns.sub.flags", "A")
resp.check(flags="QR", noflags="AA TC RD RA AD CD Z")
resp.cmp(bind)

# Check maximal UDP payload which fits into a response message.
resp = knot.dig("512resp.flags", "TXT", udp=True)
resp.check(flags="QR AA", noflags="TC RD RA AD CD Z")
resp.cmp(bind)

# TC bit - UDP.
resp = knot.dig("513resp.flags", "TXT", udp=True)
resp.check(flags="QR AA TC", noflags="RD RA AD CD Z")
resp.cmp(bind)

# No TC bit - TCP.
resp = knot.dig("513resp.flags", "TXT", udp=False)
resp.check(flags="QR AA", noflags="TC RD RA AD CD Z")
resp.cmp(bind)

# Check ANY over UDP (expects TC=1)
resp = knot.dig("flags", "ANY", udp=True)
resp.check(flags="QR AA TC", noflags="RD RA AD CD Z")
# nothing to compare

# Check ANY over TCP (expects TC=0)
resp = knot.dig("flags", "ANY", udp=False)
resp.check(flags="QR AA", noflags="TC RD RA AD CD Z")
resp.cmp(bind)

t.end()
