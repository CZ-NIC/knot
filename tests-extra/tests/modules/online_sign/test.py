#!/usr/bin/env python3

'''Check online DNSSEC signing module (just basic checks).'''

import dns.rdatatype
from dnstest.test import Test
from dnstest.utils import *
from dnstest.module import ModOnlineSign

t = Test()

ModOnlineSign.check()

knot = t.server("knot")
zones = t.zone_rnd(2, dnssec=False, records=5)
t.link(zones, knot)
knot.add_module(zones[0], ModOnlineSign())
knot.add_module(zones[1], ModOnlineSign("RSASHA256"))

def check_zone(zone, dnskey_rdata_start):
    # Check SOA record.
    soa1 = knot.dig(zone.name, "SOA", dnssec=True)
    soa1.check(rcode="NOERROR", flags="QR AA")
    soa1.check_count(1, "RRSIG")

    t.sleep(1) # Ensure different RRSIGs.

    soa2 = knot.dig(zone.name, "SOA", dnssec=True)
    soa2.check(rcode="NOERROR", flags="QR AA")
    soa2.check_count(1, "RRSIG")

    for rrset in soa1.resp.answer:
        if rrset.rdtype == dns.rdatatype.SOA:
            if rrset not in soa2.resp.answer:
                set_err("DIFFERENT SOA")
                check_log("ERROR: DIFFERENT SOA")
        elif rrset.rdtype == dns.rdatatype.RRSIG:
            if rrset in soa2.resp.answer:
                set_err("UNCHANGED RRSIG")
                check_log("ERROR: UNCHANGED RRSIG")
        else:
            set_err("UNEXPECTED RRSET")
            check_log("ERROR: UNEXPECTED RRSET")
            detail_log("%s" % rrset)

    # Check DNSKEY record.
    resp = knot.dig(zone.name, "DNSKEY", dnssec=True)
    resp.check(rcode="NOERROR", flags="QR AA")
    resp.check_count(1, "DNSKEY")
    resp.check_count(1, "RRSIG")

    for rrset in resp.resp.answer:
        if rrset.rdtype != dns.rdatatype.DNSKEY:
            continue
        else:
            isset(dnskey_rdata_start in rrset.to_text(), "DNSKEY ALGORITHM")

    # Check NSEC record.
    resp = knot.dig("nx." + zone.name, "A", dnssec=True)
    resp.check(rcode="NOERROR", flags="QR AA")
    resp.check_count(0, section="answer")
    resp.check_count(1, "SOA", section="authority")
    resp.check_count(1, "NSEC", section="authority")
    resp.check_count(2, "RRSIG", section="authority")

t.start()
knot.zones_wait(zones)

check_zone(zones[0], "256 3 13")
check_zone(zones[1], "256 3 8")

t.end()

