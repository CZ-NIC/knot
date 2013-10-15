#!/usr/bin/env python3

'''Test for server version over CH/TXT'''

import dnstest

t = dnstest.DnsTest()

ver = "ver. 1.3.1-p3"
server1 = t.server("knot", version=ver)
server2 = t.server("knot", version=True)
server3 = t.server("knot", version=False)
server4 = t.server("knot")

t.start()

# 1a) Custom version string.
resp = server1.dig("version.server", "TXT", "CH")
resp.check('"' + ver + '"')

# 1b) Bind old version of above.
resp = server1.dig("version.bind", "TXT", "CH")
resp.check('"' + ver + '"')

# 2) Automatic version string (can't be tested).
resp = server2.dig("version.server", "TXT", "CH")
resp.check(rcode="NOERROR")

# 3) Explicitly disabled.
resp = server3.dig("version.server", "TXT", "CH")
resp.check(rcode="REFUSED")

# 4) Disabled.
resp = server4.dig("version.server", "TXT", "CH")
resp.check(rcode="REFUSED")

t.end()
