#!/usr/bin/env python3

'''Test for server version over CH/TXT'''

from dnstest.test import Test

t = Test()

ver = "ver. 1.3.1-p3"
server1 = t.server("knot", version=ver)
server2 = t.server("knot")
server3 = t.server("knot", version=False)

t.start()

# 1a) Custom version string.
resp = server1.dig("version.server", "TXT", "CH")
resp.check('"' + ver + '"')

# 1b) Bind old version of above.
resp = server1.dig("version.bind", "TXT", "CH")
resp.check('"' + ver + '"')

# 2) Default version string.
resp = server2.dig("version.server", "TXT", "CH")
resp.check(rcode="NOERROR")

# 3) Disabled.
resp = server3.dig("version.server", "TXT", "CH")
resp.check(rcode="REFUSED")

t.end()
