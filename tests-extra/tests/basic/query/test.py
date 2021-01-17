#!/usr/bin/env python3

''' For various query processing states. '''

from dnstest.utils import *
from dnstest.test import Test

t = Test()
knot = t.server("knot")
knot.DIG_TIMEOUT = 2

bind = t.server("bind")
zone = t.zone("flags.")

t.link(zone, knot)
t.link(zone, bind)

t.start()

''' Negative answers. '''

# Negative (REFUSED)
resp = knot.dig("another.world", "SOA", udp=True)
resp.check(rcode="REFUSED", flags="QR", noflags="AA TC AD RA")
resp.cmp(bind)

# Negative (NXDOMAIN)
resp = knot.dig("nxdomain.flags", "A", udp=True)
resp.check(rcode="NXDOMAIN", flags="QR AA", noflags="TC AD RA")
resp.cmp(bind)

# Check that SOA TTL is limited by minimum-ttl field.
resp = knot.dig("nxdomain.flags", "A", udp=True)
resp.check_auth_soa_ttl(dnssec=False)

''' Positive answers. '''

# Positive (SOA)
resp = knot.dig("flags", "SOA", udp=True)
resp.check(rcode="NOERROR", flags="QR AA", noflags="TC AD RA")
resp.cmp(bind)

# Positive (DATA)
resp = knot.dig("dns1.flags", "A", udp=True)
resp.check(rcode="NOERROR", flags="QR AA", noflags="TC AD RA")
resp.cmp(bind)

# Positive (NODATA)
resp = knot.dig("dns1.flags", "TXT", udp=True)
resp.check(rcode="NOERROR", flags="QR AA", noflags="TC AD RA")
resp.cmp(bind)

# Positive (REFERRAL)
resp = knot.dig("sub.flags", "NS", udp=True)
resp.check(rcode="NOERROR", flags="QR", noflags="AA TC AD RA")
resp.cmp(bind, additional=True)

# Positive (REFERRAL, below delegation)
resp = knot.dig("ns.sub.flags", "A", udp=True)
resp.check(rcode="NOERROR", flags="QR", noflags="AA TC AD RA")
resp.cmp(bind, additional=True)

# Positive (REFERRAL, below delegation, ignoring empty-nonterminal during lookup)
resp = knot.dig("bellow.ns.sub.flags", "A", udp=True)
resp.check(rcode="NOERROR", flags="QR", noflags="AA TC AD RA")
resp.cmp(bind, additional=True)

# Positive (NODATA, at delegation, DS type)
resp = knot.dig("ds-sub.flags", "DS", udp=True)
resp.check(rcode="NOERROR", flags="QR AA", noflags="TC AD RA")
resp.cmp(bind, additional=True)

# Positive (REFERRAL, below delegation, DS type)
resp = knot.dig("net.ds-sub.flags", "DS", udp=True)
resp.check(rcode="NOERROR", flags="QR", noflags="AA TC AD RA")
resp.cmp(bind, additional=True)

''' ANY query type. '''
# Not comparable with BIND

''' CNAME answers. '''

# CNAME query
resp = knot.dig("cname.flags", "CNAME", udp=True)
resp.cmp(bind)

# CNAME leading to A
resp = knot.dig("cname.flags", "A", udp=True)
resp.cmp(bind)

# CNAME leading to A (NODATA)
resp = knot.dig("cname.flags", "TXT", udp=True)
resp.cmp(bind)

# CNAME leading to delegation
resp = knot.dig("cname-ns.flags", "NS", udp=True)
resp.cmp(bind, additional=True)

# CNAME leading below delegation
resp = knot.dig("cname-below-ns.flags", "A", udp=True)
resp.cmp(bind, additional=True)

# CNAME being below a delegation
resp = knot.dig("cname.below.sub.flags", "A", udp=True)
resp.cmp(bind, additional=True)

# CNAME leading out
resp = knot.dig("cname-out.flags", "A", udp=True)
resp.cmp(bind)

# CNAME leading to wildcard-covered name
resp = knot.dig("cname-wildcard.flags", "A", udp=True)
resp.cmp(bind)

# CNAME leading to wildcard-covered name (NODATA)
resp = knot.dig("cname-wildcard.flags", "TXT", udp=True)
resp.cmp(bind)

# CNAME leading to DNAME tree
resp = knot.dig("cname-dname.flags", "A", udp=True)
resp.cmp(bind)

# CNAME leading to DNAME tree (NXDOMAIN)
resp = knot.dig("cname-dname-nx.flags", "A", udp=True)
resp.cmp(bind)

# CNAME leading to DNAME tree (NODATA)
resp = knot.dig("cname-dname.flags", "TXT", udp=True)
resp.cmp(bind)

# Long CNAME loop (Bind truncates the loop at 17 records)
resp = knot.dig("ab.flags", "A", udp=True)
resp.check(rcode="NOERROR")
compare(resp.count(rtype="CNAME", section="answer"), 19, "Count of CNAME records in loop.")

''' CNAME in MX EXCHANGE. '''

# Knot puts A/AAAA for MX, SRV, and NS into Additional section of the answer.
# However, when the domain name in RDATA is an in-zone CNAME, it doesn't try
# to solve it. We expect that the resolver will be picking only useful
# information from the Additional section and following a CNAME in Additional
# is not simple.

# Leading to existing name
resp = knot.dig("cname-mx.flags", "MX", udp=True)
resp.cmp(bind)

# Leading to delegation
resp = knot.dig("cname-mx-deleg.flags", "MX", udp=True)
resp.cmp(bind)

# Leading to wildcard-covered name
resp = knot.dig("cname-mx-wc.flags", "MX", udp=True)
resp.cmp(bind)

# Leading to name outside zone
resp = knot.dig("cname-mx-out.flags", "MX", udp=True)
resp.cmp(bind)

''' DNAME answers. '''

# DNAME query (NODATA)
resp = knot.dig("dname.flags", "A", udp=True)
resp.cmp(bind)

# DNAME query (NXDOMAIN)
resp = knot.dig("nxd.dname-dangl.flags", "A", udp=True)
resp.check(rcode="NXDOMAIN")
resp.cmp(bind)

# CNAME type query on DNAME
resp = knot.dig("nxd.dname-dangl.flags", "CNAME", udp=True)
resp.check(rcode="NOERROR")
#resp.cmp(bind) NOTE: this does not work well on Bind (yet)

# DNAME type query
resp = knot.dig("dname.flags", "DNAME", udp=True)
resp.cmp(bind)

# DNAME query leading out of zone
resp = knot.dig("a.dname-out.flags", "A", udp=True)
resp.cmp(bind)

# DNAME subtree query leading to A
resp = knot.dig("a.dname.flags", "A", udp=True)
resp.cmp(bind)

# DNAME subtree query leading to NODATA
resp = knot.dig("a.dname.flags", "TXT", udp=True)
resp.cmp(bind)

# DNAME subtree query leading to CNAME
resp = knot.dig("c.dname.flags", "A", udp=True)
resp.cmp(bind)

# DNAME subtree query leading to CNAME leading to wildcard
resp = knot.dig("d.dname.flags", "A", udp=True)
resp.cmp(bind) 

# DNAME-CNAME-DNAME loop
resp = knot.dig("e.dname.flags", "A", udp=True)
resp.cmp(bind)

# DNAME-DNAME loop
resp = knot.dig("x.f.dname.flags", "A", udp=True)
resp.check(rcode="NOERROR")
resp.check_record(name="dname.flags.",          rtype="DNAME", ttl=3600, rdata="dname-tree.flags.")
resp.check_record(name="x.f.dname.flags.",      rtype="CNAME", ttl=3600, rdata="x.f.dname-tree.flags.")
resp.check_record(name="f.dname-tree.flags.",   rtype="DNAME", ttl=3600, rdata="f.f.dname-tree.flags.")
resp.check_record(name="x.f.dname-tree.flags.", rtype="CNAME", ttl=3600, rdata="x.f.f.dname-tree.flags.")
resp.check_counts(4, 0, 0)
# resp.cmp(bind) BIND responds partially unrolled CNAME loop

''' Wildcard answers. '''

# Wildcard query
resp = knot.dig("wildcard.flags", "A", udp=True)
resp.cmp(bind)

# Wildcard leading to A
resp = knot.dig("a.wildcard.flags", "A", udp=True)
resp.cmp(bind)

# Wildcard leading to A (NODATA)
resp = knot.dig("a.wildcard.flags", "TXT", udp=True)
resp.cmp(bind)

# Deeper wildcard usage
resp = knot.dig("a.a.a.wildcard.flags", "A", udp=True)
resp.cmp(bind)

# Asterisk label
resp = knot.dig("sub.*.wildcard.flags", "A", udp=True)
resp.cmp(bind)

# Asterisk label (NODATA)
resp = knot.dig("sub.*.wildcard.flags", "TXT", udp=True)
resp.cmp(bind)

# Wildcard node under asterisk label
resp = knot.dig("*.*.wildcard.flags", "A", udp=True)
resp.cmp(bind)

# Wildcard node under asterisk label (NODATA)
resp = knot.dig("*.*.wildcard.flags", "TXT", udp=True)
resp.cmp(bind)

# Wildcard under asterisk label
resp = knot.dig("a.*.wildcard.flags", "A", udp=True)
resp.cmp(bind)

# Wildcard under asterisk label (NODATA)
resp = knot.dig("a.*.wildcard.flags", "TXT", udp=True)
resp.cmp(bind)

# Wildcard under DNAME subtree
resp = knot.dig("a.wildcard.dname.flags", "A", udp=True)
resp.cmp(bind)

# Wildcard under DNAME subtree (NODATA)
resp = knot.dig("a.wildcard.dname.flags", "TXT", udp=True)
resp.cmp(bind)

# Wildcard chain to A
resp = knot.dig("a.wildcard-cname.flags", "A", udp=True)
resp.cmp(bind)

# Wildcard chain to A (NODATA)
resp = knot.dig("a.wildcard-cname.flags", "TXT", udp=True)
resp.cmp(bind)

# Wildcard chain to NS
resp = knot.dig("a.wildcard-deleg.flags", "NS", udp=True)
resp.cmp(bind, additional=True)

# Wildcard leading out
resp = knot.dig("a.wildcard-out.flags", "A", udp=True)
resp.cmp(bind)

# Wildcard leading to CNAME loop
resp = knot.dig("test.loop-entry.flags", "A", udp=True)
resp.cmp(bind)

# Wildcard-covered additional record discovery
resp = knot.dig("mx-additional.flags", "MX", udp=True)
resp.cmp(bind)

''' Varied case tests. '''

# Negative (case preservation in question)
resp = knot.dig("ANOTHER.world", "SOA", udp=True)
resp.check(rcode="REFUSED")
resp.cmp(bind)

# Positive (varied name in zone) 
resp = knot.dig("dNS1.flags", "A", udp=True)
resp.check(rcode="NOERROR")
resp.cmp(bind)

# Positive (varied zone name)
resp = knot.dig("dns1.flAGs", "A", udp=True)
resp.check(rcode="NOERROR")
resp.cmp(bind)

t.end()
