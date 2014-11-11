#!/usr/bin/env python3

'''Test for fallback IXFR->AXFR with Knot master'''

import dns.query
from dnstest.utils import *
from dnstest.test import Test

# Checks whether the transfer is an AXFR-style IXFR
def check_axfr_style_ixfr(ixfr, axfr=None):
    # 1) QTYPE == IXFR && RCODE == NOERROR
    ixfr.check_xfr()
    
    # 2) Check if Answer contains AXFR data (first SOA, second non-SOA)
    soa_count = 0
    rr_count = 0

    for msg in ixfr.resp:
        for rrset in msg.answer:
            records = rrset.to_text().split("\n")
            for record in records:
                if rr_count == 0:
                    if rrset.rdtype != dns.rdatatype.SOA:
                        set_err("First RR is not SOA")
                        return
                    else: 
                        soa_count += 1

                elif rr_count == 1:
                    if rrset.rdtype == dns.rdatatype.SOA:
                        set_err("Second RR is SOA")
                        return
                else: 
                    # OK, it has the format of AXFR
                    return

                rr_count += 1
	
	# 3) Check that number of records in IXFR and AXFR is the same
    if axfr:
        compare(ixfr.count("ANY"), axfr.count("ANY"), "Count of RRs in Answer")


t = Test()

knot = t.server("knot")
zone = t.zone("example.com.", storage=".")

t.link(zone, knot, ixfr=False)

t.start()

# Wait for AXFR to slave server.
serial_init = knot.zone_wait(zone)

# 2nd version of the zone, differing only in serial, so that there is quite
# a difference between AXFR and IXFR
knot.update_zonefile(zone, 1)
knot.reload()

resp_ixfr = knot.dig("example.com", "IXFR", serial=serial_init)

# Query for AXFR for comparison
resp_axfr = knot.dig("example.com", "AXFR")

check_axfr_style_ixfr(resp_ixfr, resp_axfr)

t.end()
