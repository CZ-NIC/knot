#!/usr/bin/env python3

'''Basic RRL functionality test'''

import dns.name

from dnstest.test import Test
from dnstest.utils import *

t = Test(stress=False)
knot = t.server("knot")
zone = t.zone("example.com.")

t.link(zone, knot)

# Enable RRL.
knot.ratelimit = 2

t.start()

knot.zone_wait(zone)
t.sleep(1)

tc_bit = False

def have_flag(response, flag):
    flag_val = dns.flags.from_text(flag)
    return (response.resp.flags & flag_val) != 0

for i in range(20):
    resp = knot.dig("example.com", "SOA", udp=True, timeout=0.05, tries=1)
    resp.check(rcode="NOERROR")

    # Check for proper flags after and before active RRL.
    if i < knot.ratelimit and have_flag(resp, "TC"):
        set_err("CHECK NO TC FLAG")
        check_log("ERROR: CHECK TC FLAG ABSENCE")
    elif i > 10 and not have_flag(resp, "TC"):
        set_err("CHECK TC FLAG")
        check_log("ERROR: CHECK TC FLAG PRESENCE")

t.end()
