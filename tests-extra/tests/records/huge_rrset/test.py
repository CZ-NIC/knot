#!/usr/bin/env python3

''' Test querying rset with too many rdata '''

import random
import dns.exception
import dns.rcode
import dns.tsig
from dnstest.utils import *
from dnstest.test import Test

t = Test(tsig=False)

master = t.server("knot")

ZONE = "example.com."
HUGE = "huge.%s" % ZONE

zone = t.zone(ZONE, storage=".")

rndfix = random.randint(1, 65000)
for i in range(1, 3000):
    zone[0].append_rndAAAA(HUGE, rndfix, i)

t.link(zone, master)

t.start()

master.zone_wait(zone)

resp = master.dig(HUGE, "AAAA", udp=True)
resp.check(rcode="NOERROR", flags="TC")
resp.check_count(0, section="answer")

resp = master.dig(HUGE, "AAAA", udp=False)
resp.check(rcode="SERVFAIL", noflags="TC")
resp.check_count(0, section="answer")

resp = master.dig(ZONE, "AXFR", tries=1, timeout=5)

got_messages = 0
last_rcode = None

try:
    for msg in resp.resp:
        got_messages += 1
        last_rcode = msg.rcode()
        compare(msg.rcode(), dns.rcode.NOERROR, "rcode")
except dns.query.TransferError as e:
    got_messages += 1
    last_rcode = e.rcode

compare(got_messages, 2, "axfr message count")
compare(last_rcode, dns.rcode.SERVFAIL, "last rcode")

t.end()
