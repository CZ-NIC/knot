#!/usr/bin/env python3

'''Test for response to IXFR request with newer serial'''

from dnstest.utils import *
from dnstest.test import Test

t = Test()

knot = t.server("knot")
zone = t.zone("example.com.")

t.link(zone, knot, ixfr=True)

t.start()

serial_init = knot.zone_wait(zone)

resp = knot.dig("example.com", "IXFR", serial=serial_init + 1)
resp.check_xfr()

compare(resp.msg_count(), 1, "Only one message")
compare(resp.count("SOA"), 1, "Only one RR in Answer section")
compare(resp.count("ANY"), 1, "Only one RR in the whole message.")

t.end()

