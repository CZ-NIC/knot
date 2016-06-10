#!/usr/bin/env python3

''' Check 'synth_record' query module synthetic responses. '''

from dnstest.test import Test
from dnstest.module import ModSynthRecord

t = Test()

ModSynthRecord.check()

# Zone indexes
FWD  = 0
REV4 = 1
REV6 = 2

# Initialize server configuration
knot = t.server("knot")
zone = t.zone("forward.", storage=".") + \
       t.zone("1.168.192.in-addr.arpa.", storage=".") + \
       t.zone("1.6.b.0.0.0.0.0.0.2.6.2.ip6.arpa.", storage=".")
t.link(zone, knot)

# Enable DNSSEC
for z in zone:
    knot.dnssec(z).enable = True

# Configure 'synth_record' modules for auto forward/reverse zones
knot.add_module(zone[FWD],  ModSynthRecord("forward", None,        None,  "192.168.0.1"))
knot.add_module(zone[FWD],  ModSynthRecord("forward", "dynamic4-", "900", "192.168.1.0-192.168.1.127"))
knot.add_module(zone[FWD],  ModSynthRecord("forward", "dynamic6-", "900", "2620:0:b61::/52"))
knot.add_module(zone[REV4], ModSynthRecord("reverse", "dynamic4-", "900", "192.168.1.0/25", "forward."))
knot.add_module(zone[REV6], ModSynthRecord("reverse", "dynamic6-", "900", "2620:0000:0b61::-2620:0000:0b61:0fff:ffff:ffff:ffff:ffff", "forward."))

t.start()

# Static address mapping
static_map = [ ("192.168.1.42", "42." + zone[REV4].name, "static4-a.forward."),
               ("2620:0:b61::42", "2.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0." + zone[REV6].name, "static6-a.forward.") ]

# Check static reverse records
for (_, reverse, forward) in static_map:
    resp = knot.dig(reverse, "PTR", dnssec=True)
    resp.check(forward, rcode="NOERROR", flags="QR AA", ttl=172800)

# Check static forward records
for (addr, reverse, forward) in static_map:
    rrtype = "AAAA" if ":" in addr else "A"
    resp = knot.dig(forward, rrtype, dnssec=True)
    resp.check(addr, rcode="NOERROR", flags="QR AA", ttl=7200)

# Check positive dynamic reverse records
dynamic_map = [ ("192.168.1.1", "1." + zone[REV4].name, "dynamic4-192-168-1-1." + zone[FWD].name),
                ("2620:0:b61::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0." + zone[REV6].name, "dynamic6-2620-0000-0b61-0000-0000-0000-0000-0001." + zone[FWD].name) ]
for (_, reverse, forward) in dynamic_map:
    resp = knot.dig(reverse, "PTR", dnssec=True)
    resp.check(forward, rcode="NOERROR", flags="QR AA", ttl=900)

# Check positive dynamic forward records (default TTL and prefix)
resp = knot.dig("192-168-0-1.forward", "A", dnssec=True)
resp.check("192.168.0.1", rcode="NOERROR", ttl=3600)

# Check positive dynamic forward records
for (addr, reverse, forward) in dynamic_map:
    rrtype = "AAAA" if ":" in addr else "A"
    resp = knot.dig(forward, rrtype, dnssec=True)
    resp.check(addr, rcode="NOERROR", flags="QR AA", ttl=900)

# Check NODATA answer for all records
for (addr, reverse, forward) in dynamic_map:
    resp = knot.dig(reverse, "TXT")
    resp.check(nordata=forward, rcode="NOERROR", flags="QR AA", ttl=172800)
    resp = knot.dig(forward, "TXT")
    resp.check(nordata=addr, rcode="NOERROR", flags="QR AA", ttl=172800)

    # Check for SERVFAIL with DNSSEC - no way to prove
    resp = knot.dig(reverse, "TXT", dnssec=True)
    resp.check(nordata=forward, rcode="SERVFAIL")
    resp = knot.dig(forward, "TXT", dnssec=True)
    resp.check(nordata=addr, rcode="SERVFAIL")

# Check "out of subnet range" query response
nxdomain_map = [ ("192.168.1.128", "128." + zone[REV4].name, "dynamic4-192-168-1-128." + zone[FWD].name),
                 ("2620:0:b61:1000::", "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1." + zone[REV6].name, "dynamic6-2620-0000-0b61-1000-0000-0000-0000-0000." + zone[FWD].name) ]
for (addr, reverse, forward) in nxdomain_map:
    rrtype = "AAAA" if ":" in addr else "A"
    resp = knot.dig(reverse, "PTR", dnssec=True)
    resp.check(rcode="NXDOMAIN", flags="QR AA")
    resp = knot.dig(forward, rrtype, dnssec=True)
    resp.check(rcode="NXDOMAIN", flags="QR AA")

# Check alias leading to synthetic name
alias_map = [ ("192.168.1.1", None, "cname4." + zone[FWD].name),
              ("2620:0:b61::1", None, "cname6." + zone[FWD].name) ]
for (addr, _, forward) in alias_map:
    rrtype = "AAAA" if ":" in addr else "A"
    resp = knot.dig(forward, rrtype, dnssec=True)
    resp.check(addr, rcode="NOERROR", flags="QR AA", ttl=900)

# Check ANY type question
for (addr, reverse, forward) in dynamic_map:
    resp = knot.dig(forward, "ANY", dnssec=True)
    resp.check(rcode="NOERROR", flags="QR AA")

t.end()
