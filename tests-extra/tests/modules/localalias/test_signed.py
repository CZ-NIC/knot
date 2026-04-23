#!/usr/bin/env python3

'''Check that `localalias` interoperates correctly with `onlinesign`:
synthesised rrsets are signed on the way out, and NODATA answers for
alias targets that are not served locally carry denying NSEC records
signed by onlinesign.

Complements test.py, which covers the unsigned path.  Same zones and
same mod-localalias attachment; this test adds mod-onlinesign to the
example. zone so that every outgoing rrset picks up an RRSIG.'''

from dnstest.test import Test
from dnstest.module import ModLocalAlias, ModOnlineSign

t = Test(address=4)

ModLocalAlias.check()
ModOnlineSign.check()

knot = t.server("knot")
zone = t.zone("example.", storage=".") + \
       t.zone("_ips.example.", storage=".")
t.link(zone, knot)

knot.add_module(zone[0], ModLocalAlias())
knot.add_module(zone[0], ModOnlineSign())

t.start()

# ----- Positive synthesis: the synthesised A rrset is signed ------------------

resp = knot.dig("www.example.", "A", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.1")
resp.check_count(1, rtype="RRSIG", section="answer")

# ----- Multiple ALIAS rdata: one RRSIG covers the merged rrset ----------------

resp = knot.dig("multi.example.", "A", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_count(2, rtype="A", section="answer")
resp.check_count(1, rtype="RRSIG", section="answer")

# ----- Direct MX on an alias node is signed the same way ----------------------

resp = knot.dig("www.example.", "MX", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="MX", rdata="10 mail.example.")
resp.check_count(1, rtype="RRSIG", section="answer")

# ----- ALIAS target not served locally -> NODATA with denying NSEC ------------

resp = knot.dig("external.example.", "A", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_count(0, rtype="A", section="answer")
resp.check_count(1, rtype="NSEC", section="authority")
resp.check_count(2, rtype="RRSIG", section="authority")  # over NSEC + SOA

# ----- Plain non-alias node: unaffected by mod-localalias, signed normally ----

resp = knot.dig("ns.example.", "A", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA")
resp.check_record(section="answer", rtype="A", rdata="192.0.2.254")
resp.check_count(1, rtype="RRSIG", section="answer")

t.end()
