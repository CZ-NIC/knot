#!/usr/bin/env python3

''' For various query processing states. '''

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
resp.check(rcode="REFUSED")
resp.cmp(bind)

# Negative (NXDOMAIN)
resp = knot.dig("nxdomain.flags", "A", udp=True)
resp.check(rcode="NXDOMAIN")
resp.cmp(bind)

''' Positive answers. '''

# Positive (DATA)
resp = knot.dig("dns1.flags", "A", udp=True)
resp.check(rcode="NOERROR")
resp.cmp(bind)

# Positive (NODATA)
resp = knot.dig("dns1.flags", "TXT", udp=True)
resp.check(rcode="NOERROR")
resp.cmp(bind)

# Positive (REFERRAL)
resp = knot.dig("sub.flags", "NS", udp=True)
resp.check(rcode="NOERROR")
resp.cmp(bind)

# Positive (REFERRAL, below delegation)
resp = knot.dig("ns.sub.flags", "A", udp=True)
resp.check(rcode="NOERROR")
resp.cmp(bind)

''' ANY query type. '''

# ANY to SOA record
resp = knot.dig("flags", "ANY", udp=True)
resp.cmp(bind)

# ANY to A record
resp = knot.dig("dns1.flags", "ANY", udp=True)
resp.cmp(bind)

# ANY to delegation point
resp = knot.dig("sub.flags", "ANY", udp=True)
resp.cmp(bind)

# ANY to CNAME record
resp = knot.dig("cname.flags", "ANY", udp=True)
resp.cmp(bind)

# ANY to DNAME record
resp = knot.dig("dname.flags", "ANY", udp=True)
resp.cmp(bind)


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
resp.cmp(bind)

# CNAME leading below delegation
resp = knot.dig("a.cname-ns.flags", "A", udp=True)
resp.cmp(bind)

# CNAME leading out
resp = knot.dig("cname-out.flags", "A", udp=True)
resp.cmp(bind)

''' DNAME answers. '''

# DNAME query
resp = knot.dig("dname.flags", "A", udp=True)
resp.cmp(bind)

# DNAME type query
resp = knot.dig("dname.flags", "DNAME", udp=True)
resp.cmp(bind)

# DNAME subtree query leading to A
resp = knot.dig("a.dname.flags", "A", udp=True)
resp.cmp(bind)

# DNAME subtree query leading to NODATA
resp = knot.dig("a.dname.flags", "TXT", udp=True)
resp.cmp(bind)

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
resp = knot.dig("wildcard.dname.flags", "A", udp=True)
resp.cmp(bind)

# Wildcard under DNAME subtree (NODATA)
resp = knot.dig("wildcard.dname.flags", "TXT", udp=True)
resp.cmp(bind)

# Wildcard chain to A
resp = knot.dig("a.wildcard-cname.flags", "A", udp=True)
resp.cmp(bind)

# Wildcard chain to A (NODATA)
resp = knot.dig("a.wildcard-cname.flags", "TXT", udp=True)
resp.cmp(bind)

# Wildcard chain to NS
resp = knot.dig("a.wildcard-deleg.flags", "NS", udp=True)
resp.cmp(bind)

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
