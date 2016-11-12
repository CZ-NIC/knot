#!/usr/bin/env python3

''' Check 'rosedb' query module functionality. '''

import os.path
from dnstest.test import Test
from dnstest.utils import *
from dnstest.module import ModRosedb

t = Test()

ModRosedb.check()

# Initialize server configuration.
zone = t.zone("example.com.")
knot = t.server("knot")
t.link(zone, knot)

# Attach rosedb.
module = ModRosedb(os.path.join(knot.dir, "rosedb"))
knot.add_module(None, module)

t.start()

# Check before rosedb applied.
resp = knot.dig("mail.example.com", "A")
resp.check(rcode="NOERROR", rdata="192.0.2.3", ttl=3600, flags="AA")

# Set rosedb records.
module.add_record("mail.example.com",  "A",    "1000", "127.0.0.1")
module.add_record("mail6.example.com", "AAAA", "1000", "::1")
knot.reload()

# Check if zone record is overridden with rosedb.
resp = knot.dig("mail.example.com", "A")
resp.check(rcode="NOERROR", rdata="127.0.0.1", ttl=1000, noflags="AA")

# Check for subdomain match.
resp = knot.dig("sub.sub.mail.example.com", "A")
resp.check(rcode="NOERROR", rdata="127.0.0.1", ttl=1000, noflags="AA")

# Check for new record.
resp = knot.dig("mail6.example.com", "AAAA")
resp.check(rcode="NOERROR", rdata="::1", ttl=1000, noflags="AA")

# Check for new record with bad type (NODATA).
resp = knot.dig("mail6.example.com", "A")
resp.check(rcode="NOERROR", noflags="AA")
compare(resp.count(), 0, "A count")

# Add authority information.
module.add_record("example.net",     "SOA", "1", "ns1 host 1 3600 60 3600 3600")
module.add_record("example.net",     "NS",  "2", "ns1.example.net")
module.add_record("ns1.example.net", "A",   "3", "127.0.0.2")
knot.reload()

# Check for authoritative answer.
resp = knot.dig("example.net", "NS")
resp.check(rcode="NOERROR", rdata="ns1.example.net.", ttl=2, flags="AA")
resp.check_count(1, rtype="SOA", section="authority")

# Check for NXDOMAIN.
resp = knot.dig("example.net", "MX")
resp.check(rcode="NXDOMAIN", flags="AA")
resp.check_count(1, rtype="SOA", section="authority")

t.end()
