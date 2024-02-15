#!/usr/bin/env python3

''' Check 'authsignal' query module synthetic responses. '''

from dnstest.test import Test
from dnstest.module import ModAuthSignal, ModOnlineSign
import random

t = Test()

ModAuthSignal.check()

onlinesign = random.choice([True, False])
try:
    ModOnlineSign.check()
except:
    onlinesign = False

# Initialize server configuration
knot = t.server("knot")
zone = t.zone("_signal.dns1.", storage=".") + \
       t.zone("example.net.", storage=".")
t.link(zone, knot)

# Configure 'authsignal' module
knot.add_module(zone[0], ModAuthSignal())
if onlinesign:
    knot.add_module(zone[0], ModOnlineSign())

def check_rrsig(resp, expect):
    resp.check_count(expect if onlinesign else 0, rtype="RRSIG", section="answer")

def check_nsec(resp, expect):
    resp.check_count(expect if onlinesign else 0, rtype="NSEC", section="authority")
    resp.check_count(expect + 1 if onlinesign else 0, rtype="RRSIG", section="authority") # +1 for SOA

t.start()

# example.net CDS/CDNSKEY mapping
records = [("CDS", "45985 13 2 84C852BE675B452191673019B3B5D81C211F22BC3B9DC3C0848A6379CB0261A4"),
           ("CDNSKEY", "257 3 13 1d5lDu1o1HEn2lx+YAi2xsjOVE44wjBca/NMlKORpL7C4QERGUztd9SLo0r55+j5P7uHFoeGEnLM+ppwWwdH5A==")]

# Check CDS/CDNSKEY synthesis
for (rdtype, result) in records:
    resp = knot.dig("_dsboot.example.net._signal.dns1.", rdtype, dnssec=True)
    resp.check(result, rcode="NOERROR", flags="QR AA", ttl=7200)
    check_rrsig(resp, 1)

# Check NODATA on incorrect qtype
resp = knot.dig("_dsboot.example.net._signal.dns1.", "AAAA", dnssec=True)
resp.check(rcode="NOERROR", flags="QR AA")
check_nsec(resp, 1)

# Check NODATA on potential empty non-terminals
for (rdtype, _) in records:
    resp = knot.dig("example.net._signal.dns1.", rdtype, dnssec=True)
    resp.check(rcode="NOERROR", flags="QR AA")
    check_nsec(resp, 1)

# Check NXDOMAIN on unknown domains
for (rdtype, _) in records:
    resp = knot.dig("_dsboot.example.com._signal.dns1.", rdtype, dnssec=True)
    exp_rcode = "NXDOMAIN" if not onlinesign else "NOERROR"  # Onlinesign promotes NXDOMAIN to NODATA
    resp.check(rcode=exp_rcode, flags="QR AA")
    check_nsec(resp, 1)

# Check SERVFAIL if the target zone is expired
knot.ctl("-f zone-purge " + zone[1].name)
t.sleep(1)
for (rdtype, result) in records:
    resp = knot.dig("_dsboot.example.net._signal.dns1.", rdtype, dnssec=True)
    resp.check(nordata=result, rcode="SERVFAIL")

t.end()
