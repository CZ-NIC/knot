#!/usr/bin/env python3
"""
Basic checks for CNAME following.

- Query for CNAME, NSEC, RRSIG is not followed.
- Query for ANY meta type is not followed.
- Query for any other type is followed.
- DNAME CNAME is too long.

And some ANY checks.
"""

from dnstest.test import Test

t = Test()

knot = t.server("knot")
zone = t.zone("follow", storage=".")
t.link(zone, knot)

t.start()

# follow CNAME (type exists)

resp = knot.dig("test.follow", "AAAA")
resp.check(rcode="NOERROR", flags="AA")
resp.check_rr("answer", "test.follow", "CNAME")
resp.check_rr("answer", "follow", "AAAA")
resp.check_empty("authority")

# follow CNAME (type doesn't exist)

resp = knot.dig("test.follow", "TXT")
resp.check(rcode="NOERROR", flags="AA")
resp.check_rr("answer", "test.follow", "CNAME")
resp.check_no_rr("answer", "test")
resp.check_rr("authority", "follow", "SOA")

# query for CNAME

resp = knot.dig("test.follow", "CNAME")
resp.check(rcode="NOERROR", flags="AA")
resp.check_rr("answer", "test.follow", "CNAME")
resp.check_no_rr("answer", "test")
resp.check_empty("authority")

# CNAME loop

resp = knot.dig("loop.follow", "AAAA", udp=False)
resp.check(rcode="NOERROR")
resp.check_count(3, rtype="CNAME")

# CNAME chain too long

resp = knot.dig("chain.follow", "AAAA", udp=False)
resp.check(rcode="NOERROR")
resp.check_count(5, rtype="CNAME")
resp.check_count(0, rtype="AAAA")

# query for RRSIG

resp = knot.dig("test.follow", "RRSIG")
resp.check(rcode="NOERROR", flags="AA")
resp.check_rr("answer", "test.follow", "RRSIG")
resp.check_no_rr("answer", "test")
resp.check_empty("authority")

# query for NSEC

resp = knot.dig("test.follow", "NSEC")
resp.check(rcode="NOERROR", flags="AA")
resp.check_rr("answer", "test.follow", "NSEC")
resp.check_no_rr("answer", "test")
resp.check_empty("authority")

# query for ANY

resp = knot.dig("any.follow", "ANY")
resp.check(rcode="NOERROR", flags="AA")
resp.check_rr("answer", "any.follow", "A")
resp.check_no_rr("answer", "any.follow", "AAAA")
resp.check_no_rr("answer", "any.follow", "NSEC")
resp.check_no_rr("answer", "any.follow", "RRSIG")

# query for ANY with DNSSEC

resp = knot.dig("any.follow", "ANY", dnssec=True)
resp.check(rcode="NOERROR", flags="AA")
resp.check_rr("answer", "any.follow", "A")
resp.check_no_rr("answer", "any.follow", "AAAA")
resp.check_no_rr("answer", "any.follow", "NSEC")
resp.check_rr("answer", "any.follow", "RRSIG")

# query for ANY on CNAME

resp = knot.dig("test.follow", "ANY")
resp.check(rcode="NOERROR", flags="AA")
resp.check_rr("answer", "test.follow", "CNAME")
resp.check_empty("authority")

# DNAME synthesizes too long CNAME

resp = knot.dig("63o-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx." +
                "63o-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx." +
                "63o-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx." +
                "50o-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.big.follow.",
                "CNAME", udp=True, dnssec=True)
resp.check(rcode="YXDOMAIN")
resp.check_record(section="answer", rtype="DNAME", rdata="uhuh.follow.")
resp.check_rr(section="answer", rname="big.follow.", rtype="RRSIG")

# query for DNAME-synthesized-CNAME exactly

resp = knot.dig("nxd.big.follow.", "CNAME")
resp.check(rcode="NOERROR")
resp.check_rr("answer", "big.follow.", "DNAME")
resp.check_rr("answer", "nxd.big.follow.", "CNAME")

t.end()
