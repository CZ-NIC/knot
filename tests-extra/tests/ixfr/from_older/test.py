#!/usr/bin/env python3

'''Test for response to IXFR request with newer serial'''

from dnstest.utils import *
from dnstest.test import Test

t = Test()

knot = t.server("knot")
zone = t.zone("example.com.")

t.link(zone, knot, ixfr=True)

t.start()

serial_init = knot.zones_wait(zone)

resp = knot.dig("example.com", "IXFR", serial=serial_init["example.com."]+1)

count = 0
for msg in resp.resp:
        count += len(msg.answer)

compare(count, 1, "Only one RR in Answer section")

#TODO: Can I somehow check that the only RR is SOA?

t.end()

