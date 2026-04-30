#!/usr/bin/env python3

'''Check the `alias` query module synthesises ALIAS records at query time
from locally-served target zones.

Each run randomly picks DNSSEC mode: when DNSSEC is enabled, mod-onlinesign
is attached alongside mod-alias and synthesised rrsets are checked for an
accompanying RRSIG; the NODATA-on-external-target case is also verified to
carry a denying NSEC + RRSIGs in the authority section.'''

import random
from dnstest.test import Test
from dnstest.module import ModAlias, ModOnlineSign

DNSSEC = random.choice([True, False])

t = Test()

ModAlias.check()
ModOnlineSign.check()

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
knot.add_module(zone[0], ModAlias())
if DNSSEC:
    knot.add_module(zone[0], ModOnlineSign())

t.start()

# ----- Pure ALIAS: www -> web._ips.example. --------------------------------

resp = knot.dig("www.example.", "A", dnssec=DNSSEC)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.1")
if DNSSEC:
    resp.check_count(1, rtype="RRSIG", section="answer")

resp = knot.dig("www.example.", "AAAA", dnssec=DNSSEC)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="AAAA", rdata="2001:db8::1")
if DNSSEC:
    resp.check_count(1, rtype="RRSIG", section="answer")

# ----- Explicit ALIAS-type query returns the raw record (diagnostics) ------
# An explicit TYPE65401 query is the only way to inspect the ALIAS itself.

resp = knot.dig("www.example.", "TYPE65401", dnssec=DNSSEC)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_count(1, rtype="TYPE65401", section="answer")
resp.check_count(0, rtype="A", section="answer")
if DNSSEC:
    resp.check_count(1, rtype="RRSIG", section="answer")

# ----- Non-A/AAAA query on an ALIAS node passes through to the resolver ----
# www.example. has both an ALIAS and a direct MX.  The module does not touch
# MX queries, so the standard resolver returns the direct MX rrset as normal.

resp = knot.dig("www.example.", "MX", dnssec=DNSSEC)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="MX", rdata="10 mail.example.")
if DNSSEC:
    resp.check_count(1, rtype="RRSIG", section="answer")

# ----- ALIAS target not served locally -> NODATA ---------------------------
# When signed, NODATA carries a denying NSEC plus RRSIGs (over NSEC and SOA).

resp = knot.dig("external.example.", "A", dnssec=DNSSEC)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_count(0, rtype="A", section="answer")
if DNSSEC:
    resp.check_count(1, rtype="SOA", section="authority")
    resp.check_count(1, rtype="NSEC", section="authority")
    resp.check_count(2, rtype="RRSIG", section="authority")

# ----- Multiple ALIAS rdata on one node merge both targets' A records ------

resp = knot.dig("multi.example.", "A", dnssec=DNSSEC)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_count(2, rtype="A", section="answer")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.1")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.2")
if DNSSEC:
    resp.check_count(1, rtype="RRSIG", section="answer")

# ----- Self-referential ALIAS, no A on target -> NODATA --------------------

resp = knot.dig("loop.example.", "A", dnssec=DNSSEC)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_count(0, rtype="A", section="answer")
if DNSSEC:
    resp.check_count(1, rtype="SOA", section="authority")
    resp.check_count(1, rtype="NSEC", section="authority")
    resp.check_count(2, rtype="RRSIG", section="authority")

# ----- Self-referential ALIAS with coexisting direct A returns the A -------
# The module finds the same node and merges in the direct A; no infinite loop.

resp = knot.dig("loop2.example.", "A", dnssec=DNSSEC)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="10.0.0.4")
if DNSSEC:
    resp.check_count(1, rtype="RRSIG", section="answer")

# ----- ALIAS + direct A -> both appear (additive) --------------------------

resp = knot.dig("both.example.", "A", dnssec=DNSSEC)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_count(2, rtype="A", section="answer")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.1")
resp.check_record(section="answer", rtype="A", rdata="10.0.0.3")
if DNSSEC:
    resp.check_count(1, rtype="RRSIG", section="answer")

# ----- TTL cap: min(alias_ttl=600, target_ttl=300) = 300 -------------------

resp = knot.dig("lowttl.example.", "A", dnssec=DNSSEC)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.1", ttl=300)
if DNSSEC:
    resp.check_count(1, rtype="RRSIG", section="answer")

# ----- Wildcard ALIAS; specific plain-A override wins -----------------
# over.wild1 has a direct A (no ALIAS) so the normal wildcard miss applies;
# any other label under *.wild1 synthesises from the wildcard's ALIAS target.

resp = knot.dig("over.wild1.example.", "A", dnssec=DNSSEC)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="10.0.0.1")
if DNSSEC:
    resp.check_count(1, rtype="RRSIG", section="answer")

resp = knot.dig("any.wild1.example.", "A", dnssec=DNSSEC)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.1")
if DNSSEC:
    resp.check_count(1, rtype="RRSIG", section="answer")

# ----- Wildcard plain A; specific ALIAS override synthesises --------------

resp = knot.dig("login.wild2.example.", "A", dnssec=DNSSEC)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.1")
if DNSSEC:
    resp.check_count(1, rtype="RRSIG", section="answer")

resp = knot.dig("other.wild2.example.", "A", dnssec=DNSSEC)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="10.0.0.2")
if DNSSEC:
    resp.check_count(1, rtype="RRSIG", section="answer")

# ----- Wildcard ALIAS; specific ALIAS points at a different target --------

resp = knot.dig("any.wild3.example.", "A", dnssec=DNSSEC)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.1")
if DNSSEC:
    resp.check_count(1, rtype="RRSIG", section="answer")

resp = knot.dig("other.wild3.example.", "A", dnssec=DNSSEC)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.2")
if DNSSEC:
    resp.check_count(1, rtype="RRSIG", section="answer")

# ----- Non-A/AAAA queries pass through; ALIAS target's MX is ignored ------
# mixmx has ALIAS to mail._ips.example. (which has an MX) plus a direct MX.
# Only the direct MX must appear; the module no longer synthesises non-address
# types from the target.  An A query on the same node still synthesises from
# the target's A record.

resp = knot.dig("mixmx.example.", "MX", dnssec=DNSSEC)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_count(1, rtype="MX", section="answer")
resp.check_record(section="answer", rtype="MX", rdata="20 mx.example.")
if DNSSEC:
    resp.check_count(1, rtype="RRSIG", section="answer")

resp = knot.dig("mixmx.example.", "A", dnssec=DNSSEC)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.3")
if DNSSEC:
    resp.check_count(1, rtype="RRSIG", section="answer")

# ----- ANY is passed through to the standard resolver --------------------
# The module doesn't intercept ANY; the raw ALIAS record is returned as-is,
# with no synthesis from the target.  Knot's default for ANY is one rrset per
# node (RFC 8482 style), so we use an ALIAS-only node for a deterministic
# assertion.

resp = knot.dig("lowttl.example.", "ANY", dnssec=DNSSEC)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_count(1, rtype="TYPE65401", section="answer")
resp.check_count(0, rtype="A", section="answer")
resp.check_count(0, rtype="AAAA", section="answer")
if DNSSEC:
    resp.check_count(1, rtype="RRSIG", section="answer")

# ----- Plain (non-ALIAS) nodes are unaffected by the module ---------------

resp = knot.dig("ns.example.", "A", dnssec=DNSSEC)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.254")
if DNSSEC:
    resp.check_count(1, rtype="RRSIG", section="answer")

resp = knot.dig("mx.example.", "A", dnssec=DNSSEC)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.253")

# NXDOMAIN for name not in any zone
resp = knot.dig("nonexistent.example.", "A", dnssec=DNSSEC)
if DNSSEC:
    resp.check(rcode="NOERROR") # Specific of mod-onlinesign
    resp.check_count(1, rtype="SOA", section="authority")
    resp.check_count(1, rtype="NSEC", section="authority")
    resp.check_count(2, rtype="RRSIG", section="authority")
else:
    resp.check(rcode="NXDOMAIN")

t.end()
