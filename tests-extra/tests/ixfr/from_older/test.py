#!/usr/bin/env python3

'''Test for response to IXFR request with newer serial'''

from dnstest.utils import *
from dnstest.test import Test

t = Test(tsig=False)

knot = t.server("knot")
zone = t.zone("example.com.")

t.link(zone, knot, ixfr=True)

t.start()

serial_init = knot.zone_wait(zone)

resp = knot.kdig("example.com", "IXFR=" + str(serial_init + 1))
normalized_lines = [
    " ".join(line.split())
    for line in resp.splitlines()
    if line.strip() and not line.startswith(";;")
]
compare(len(normalized_lines), 1, "Only one record")
expected = "example.com. 3600 IN SOA dns1.example.com. hostmaster.example.com. 2010111201 10800 3600 1209600 7200"
isset(expected in normalized_lines, "SOA match")

t.end()

