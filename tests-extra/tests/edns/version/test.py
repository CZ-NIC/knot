#!/usr/bin/env python3

'''Test for EDNS version'''

from dnstest.test import Test
from dnstest.utils import *

t = Test()

server = t.server("knot")
zone = t.zone("example.com.")

t.link(zone, server)

t.start()

# Supported EDNS version 0.
resp = server.dig("example.com", "SOA", edns=0)
resp.check(rcode="NOERROR", edns_version=0)

# Unsupported EDNS version 1.
resp = server.dig("example.com", "SOA", edns=1)
resp.check(rcode="BADVERS", edns_version=0)
compare(resp.count(section="answer"), 0, "Answer count")
compare(resp.count(section="authority"), 0, "Authority count")
compare(resp.count(section="additional"), 0, "Additional count")


t.end()
