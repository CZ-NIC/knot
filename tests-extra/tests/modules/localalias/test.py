#!/usr/bin/env python3

'''Check the `localalias` query module synthesises ALIAS records at query time
from locally-served target zones.  Ported from the unit tests that previously
lived at tests/knot/test_alias_synthesis.c (which exercised a core-nameserver
implementation before it was moved into a module).'''

from dnstest.test import Test
from dnstest.module import ModLocalAlias

t = Test(address=4)

ModLocalAlias.check()

# Two zones: example. has the ALIAS records, _ips.example. holds the A/AAAA
# target rrsets referenced by them.  Both are served by the same knotd so the
# module's zonedb lookup succeeds for local targets and falls through for the
# `external.tld.` target used in the NODATA test.
knot = t.server("knot")
zone = t.zone("example.", storage=".") + \
       t.zone("_ips.example.", storage=".")
t.link(zone, knot)

# Attach the module to example. only; _ips.example. is a target zone
# and holds no ALIAS records of its own.  No per-instance config.
knot.add_module(zone[0], ModLocalAlias())

t.start()

# ----- 1. Pure ALIAS: www -> web._ips.example. --------------------------------

resp = knot.dig("www.example.", "A")
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.1")

resp = knot.dig("www.example.", "AAAA")
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="AAAA", rdata="2001:db8::1")

# ----- 2. Explicit ALIAS-type query returns the raw record (diagnostics) ------
# An explicit TYPE65401 query is the only way to inspect the ALIAS itself.

resp = knot.dig("www.example.", "TYPE65401")
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_count(1, rtype="TYPE65401", section="answer")
resp.check_count(0, rtype="A", section="answer")

# ----- 3. Coexisting direct MX on an ALIAS node is unaffected -----------------

resp = knot.dig("www.example.", "MX")
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="MX", rdata="10 mail.example.")

# ----- 4. ALIAS target not served locally -> NODATA ---------------------------

resp = knot.dig("external.example.", "A")
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_count(0, rtype="A", section="answer")

# ----- 5. Multiple ALIAS rdata on one node merge both targets' A records ------

resp = knot.dig("multi.example.", "A")
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_count(2, rtype="A", section="answer")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.1")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.2")

# ----- 6. Self-referential ALIAS, no A on target -> NODATA --------------------

resp = knot.dig("loop.example.", "A")
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_count(0, rtype="A", section="answer")

# ----- 7. Self-referential ALIAS with coexisting direct A returns the A -------
# The module finds the same node and merges in the direct A; no infinite loop.

resp = knot.dig("loop2.example.", "A")
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="10.0.0.4")

# ----- 8. ALIAS + direct A -> both appear (additive) --------------------------

resp = knot.dig("both.example.", "A")
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_count(2, rtype="A", section="answer")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.1")
resp.check_record(section="answer", rtype="A", rdata="10.0.0.3")

# ----- 9. TTL cap: min(alias_ttl=600, target_ttl=300) = 300 -------------------

resp = knot.dig("lowttl.example.", "A")
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.1", ttl=300)

# ----- 10. Wildcard ALIAS; specific plain-A override wins -----------------
# over.wild1 has a direct A (no ALIAS) so the normal wildcard miss applies;
# any other label under *.wild1 synthesises from the wildcard's ALIAS target.

resp = knot.dig("over.wild1.example.", "A")
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="10.0.0.1")

resp = knot.dig("any.wild1.example.", "A")
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.1")

# ----- 11. Wildcard plain A; specific ALIAS override synthesises --------------

resp = knot.dig("login.wild2.example.", "A")
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.1")

resp = knot.dig("other.wild2.example.", "A")
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="10.0.0.2")

# ----- 12. Wildcard ALIAS; specific ALIAS points at a different target --------

resp = knot.dig("any.wild3.example.", "A")
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.1")

resp = knot.dig("other.wild3.example.", "A")
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.2")

# ----- 13. MX query merges direct MX with ALIAS-target MX (additive) ----------

resp = knot.dig("mixmx.example.", "MX")
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_count(2, rtype="MX", section="answer")
resp.check_record(section="answer", rtype="MX", rdata="10 mx.example.")
resp.check_record(section="answer", rtype="MX", rdata="20 mx.example.")

# ----- 14. ANY is passed through to the standard resolver --------------------
# The module doesn't intercept ANY; the raw ALIAS record is returned as-is,
# with no synthesis from the target.  Knot's default for ANY is one rrset per
# node (RFC 8482 style), so we use an ALIAS-only node for a deterministic
# assertion.

resp = knot.dig("lowttl.example.", "ANY")
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_count(1, rtype="TYPE65401", section="answer")
resp.check_count(0, rtype="A", section="answer")
resp.check_count(0, rtype="AAAA", section="answer")

# ----- 15. Plain (non-ALIAS) nodes are unaffected by the module ---------------

resp = knot.dig("ns.example.", "A")
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.254")

resp = knot.dig("mx.example.", "A")
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.253")

# NXDOMAIN for name not in any zone
resp = knot.dig("nonexistent.example.", "A")
resp.check(rcode="NXDOMAIN")

t.end()
