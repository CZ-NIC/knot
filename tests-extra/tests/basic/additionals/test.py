#!/usr/bin/env python3
"""

Basic checks of Additional section content.

- Query into a delegation scope adds glue into additionals.
- Query for NS/MX/SRV adds target A+AAAA into additionals.
- Query for other types (like PTR) does NOT cause lookup of additionals.
- Query for NS/MX/SRV pointing to CNAME does NOT cause lookup of additionals.

"""

from dnstest.test import Test

t = Test()

knot = t.server("knot")
zone = t.zone("test", storage=".")
t.link(zone, knot)

t.start()

# NS authoritative

resp = knot.dig("test", "NS")
resp.check(rcode="NOERROR", flags="AA")
resp.check_rr("answer", "test", "NS")
resp.check_rr("additional", "a.ns.test", "A")
resp.check_rr("additional", "a.ns.test", "AAAA")
resp.check_rr("additional", "b.ns.test", "AAAA")

# NS delegation

resp = knot.dig("www.deleg.test", "A")
resp.check(rcode="NOERROR", noflags="AA")
resp.check_empty(section="answer")
resp.check_rr("authority", "deleg.test", "NS")
resp.check_rr("additional", "a.ns.deleg.test", "A")
resp.check_rr("additional", "a.ns.deleg.test", "AAAA")

# MX record

resp = knot.dig("mx.test", "MX")
resp.check(rcode="NOERROR", flags="AA")
resp.check_rr("answer", "mx.test", "MX")
resp.check_rr("additional", "a.mail.test", "A")
resp.check_rr("additional", "b.mail.test", "AAAA")

# SRV record (only AAAA in additionals)

resp = knot.dig("srv.test", "SRV")
resp.check(rcode="NOERROR", flags="AA")
resp.check_rr("answer", "srv.test", "SRV")
resp.check_rr("additional", "b.service.test", "AAAA")

# PTR record (no additionals expected)

resp = knot.dig("ptr.test", "PTR")
resp.check(rcode="NOERROR", flags="AA")
resp.check_rr("answer", "ptr.test", "PTR")
resp.check_empty("additional")

# MX through CNAME (no additionals expected)

resp = knot.dig("mx-cname.test", "MX")
resp.check(rcode="NOERROR", flags="AA")
resp.check_rr("answer", "mx-cname.test", "MX")
resp.check_empty("additional")

t.stop()
