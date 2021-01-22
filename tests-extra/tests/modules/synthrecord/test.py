#!/usr/bin/env python3

''' Check 'synth_record' query module synthetic responses. '''

from dnstest.test import Test
from dnstest.module import ModSynthRecord, ModOnlineSign
import random
import re

t = Test()

ModSynthRecord.check()

onlinesign = random.choice([True, False])
try:
    ModOnlineSign.check()
except:
    onlinesign = False

# Zone indexes
FWD  = 0
REV4 = 1
REV6 = 2
REV  = 3

# Initialize server configuration
knot = t.server("knot")
zone = t.zone("forward.", storage=".") + \
       t.zone("1.168.192.in-addr.arpa.", storage=".") + \
       t.zone("1.6.b.0.0.0.0.0.0.2.6.2.ip6.arpa.", storage=".") + \
       t.zone("ip6.arpa.", storage=".")
t.link(zone, knot)

# Configure 'synth_record' modules for auto forward/reverse zones
knot.add_module(zone[FWD],  ModSynthRecord("forward", None,        None, "192.168.0.1"))
knot.add_module(zone[FWD],  ModSynthRecord("forward", "dynamic-", "900", "[ 192.168.1.0-192.168.1.127, 2620:0:b61::/52 ]"))
knot.add_module(zone[REV4], ModSynthRecord("reverse", "dynamic-", "900", "[ 192.168.3.0/25, 192.168.1.0/25, 192.168.2.0/25 ]", "forward."))
knot.add_module(zone[REV6], ModSynthRecord("reverse", "dynamic-", "900", "2620:0000:0b61::-2620:0000:0b61:0fff:ffff:ffff:ffff:ffff", "forward."))
knot.add_module(zone[REV],  ModSynthRecord("reverse", "",         "900", "::0/0", "forward."))

if onlinesign:
    for z in zone:
        knot.add_module(z, ModOnlineSign())

def check_rrsig(resp, expect):
    resp.check_count(expect if onlinesign else 0, rtype="RRSIG", section="answer")

def check_nsec(resp, expect):
    resp.check_count(expect if onlinesign else 0, rtype="NSEC", section="authority")
    resp.check_count(expect + 1 if onlinesign else 0, rtype="RRSIG", section="authority") # +1 for SOA

t.start()

# Static address mapping
static_map = [ ("192.168.1.42", "42." + zone[REV4].name, "static4-a.forward."),
               ("2620:0:b61::42", "2.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0." + zone[REV6].name, "static6-a.forward.") ]

# Check static reverse records
for (_, reverse, forward) in static_map:
    resp = knot.dig(reverse, "PTR", dnssec=True)
    resp.check(forward, rcode="NOERROR", flags="QR AA", ttl=172800)
    check_rrsig(resp, 1)

# Check static forward records
for (addr, reverse, forward) in static_map:
    rrtype = "AAAA" if ":" in addr else "A"
    resp = knot.dig(forward, rrtype, dnssec=True)
    resp.check(addr, rcode="NOERROR", flags="QR AA", ttl=7200)
    check_rrsig(resp, 1)

# Check positive dynamic reverse records
dynamic_map = [ ("192.168.1.1", "1." + zone[REV4].name, "dynamic-192-168-1-1." + zone[FWD].name),
                ("2620:0:b61::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0." + zone[REV6].name, "dynamic-2620-0-b61--1." + zone[FWD].name) ]
#                       <     > <     > <     > <     > <     > <     > <     > <     >
reverse_extra = [ ("", "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0." + zone[REV].name, "0-0--0." + zone[FWD].name),
                  ("", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0." + zone[REV].name, "0-0--1." + zone[FWD].name),
                  ("", "0.0.0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0." + zone[REV].name, "0-0--1-0." + zone[FWD].name),
                  ("", "0.0.0.0.0.0.0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0." + zone[REV].name, "0-0--1-0-0." + zone[FWD].name),
                  ("", "0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0." + zone[REV].name, "0-0--1-0-0-0." + zone[FWD].name),
                  ("", "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0." + zone[REV].name, "0-0-0-1--0." + zone[FWD].name),
                  ("", "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.0.0.0.0.0.0." + zone[REV].name, "0-0-1--0." + zone[FWD].name),
                  ("", "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.0.0." + zone[REV].name, "0-1--0." + zone[FWD].name),
                  ("", "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0." + zone[REV].name, "1-0--0." + zone[FWD].name),
                  ("", "0.0.0.1.0.0.2.0.0.3.0.0.4.0.0.0.a.b.c.d.0.e.f.0.a.a.0.0.0.0.b.b." + zone[REV].name, "bb00-aa-fe0-dcba-4-30-200-1000." + zone[FWD].name) ]
for (_, reverse, forward) in dynamic_map + reverse_extra:
    resp = knot.dig(reverse, "PTR", dnssec=True)
    resp.check(forward, rcode="NOERROR", flags="QR AA", ttl=900)
    check_rrsig(resp, 1)

# Check positive dynamic forward records (default TTL and prefix)
resp = knot.dig("192-168-0-1.forward", "A", dnssec=True)
resp.check("192.168.0.1", rcode="NOERROR", ttl=3600)
check_rrsig(resp, 1)

# Check positive dynamic forward records
forward_extra = [ ("2620:0:b61::", "", "dynamic-2620-0-b61--." + zone[FWD].name),
                  ("2620:0:b61::1", "", "dynamic-2620-0-b61--1." + zone[FWD].name),
                  ("2620:0:b61::10", "", "dynamic-2620-0-b61--10." + zone[FWD].name),
                  ("2620:0:b61::100", "", "dynamic-2620-0-b61--100." + zone[FWD].name),
                  ("2620:0:b61::1000", "", "dynamic-2620-0-b61--1000." + zone[FWD].name),
                  ("2620:0:b61::", "", "dynamic-2620-0-b61-0-0-0-0-0." + zone[FWD].name) ]
for (addr, reverse, forward) in dynamic_map + forward_extra:
    rrtype = "AAAA" if ":" in addr else "A"
    resp = knot.dig(forward, rrtype, dnssec=True)
    resp.check(addr, rcode="NOERROR", flags="QR AA", ttl=900)
    check_rrsig(resp, 1)

# Check NODATA answer for all records
for (addr, reverse, forward) in dynamic_map:
    resp = knot.dig(reverse, "TXT", dnssec=True)
    resp.check(nordata=forward, rcode="NOERROR", flags="QR AA", ttl=172800)
    check_nsec(resp, 1)
    resp = knot.dig(forward, "TXT", dnssec=True)
    resp.check(nordata=addr, rcode="NOERROR", flags="QR AA", ttl=172800)
    check_nsec(resp, 1)

# Check NODATA on resulting empty-non-terminals
for (_, reverse, forward) in dynamic_map + reverse_extra:
    while knot.dig(reverse, "SOA").count("SOA") < 1: # until we hit zone apex
        reverse = re.sub(r'^[^.]*\.', '', reverse) # cut out the leftmost label
        resp = knot.dig(reverse, "PTR", dnssec=True)
        resp.check(nordata=forward, rcode="NOERROR", flags="QR AA", ttl=172800)
        check_nsec(resp, 1)

# Check "out of subnet range" query response
nxdomain_map = [ ("192.168.1.128", "128." + zone[REV4].name, "dynamic-192-168-1-128." + zone[FWD].name),
                 ("2620:0:b61:1000::", "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1." + zone[REV6].name,
                  "dynamic-2620-0000-0b61-1000-0000-0000-0000-0000." + zone[FWD].name) ]
for (addr, reverse, forward) in nxdomain_map:
    rrtype = "AAAA" if ":" in addr else "A"
    exp_rcode = "NXDOMAIN" if not onlinesign else "NOERROR" # Onlinesign promotes NXDOMAIN to NODATA
    resp = knot.dig(reverse, "PTR", dnssec=True)
    resp.check(rcode=exp_rcode, flags="QR AA")
    check_nsec(resp, 1)
    resp = knot.dig(forward, rrtype, dnssec=True)
    resp.check(rcode=exp_rcode, flags="QR AA")
    check_nsec(resp, 1)

# Check alias leading to synthetic name
alias_map = [ ("192.168.1.1", None, "cname4." + zone[FWD].name),
              ("2620:0:b61::1", None, "cname6." + zone[FWD].name) ]
for (addr, _, forward) in alias_map:
    rrtype = "AAAA" if ":" in addr else "A"
    resp = knot.dig(forward, rrtype, dnssec=True)
    resp.check(addr, rcode="NOERROR", flags="QR AA", ttl=900)
    check_rrsig(resp, 2)

# Check ANY type question
for (addr, reverse, forward) in dynamic_map:
    resp = knot.dig(forward, "ANY", dnssec=True)
    resp.check(rcode="NOERROR", flags="QR AA")
    check_rrsig(resp, 1)

t.end()
