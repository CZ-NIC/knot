#!/usr/bin/env python3

'''Test for server identification over CH/TXT'''

from dnstest.test import Test

t = Test()

name = "Knot DNS server name"
server1 = t.server("knot", ident=name)
server2 = t.server("knot", ident=True)
server3 = t.server("knot", ident=False)
server4 = t.server("knot")

t.start()

# 1a) Custom identification string.
resp = server1.dig("id.server", "TXT", "CH")
resp.check('"' + name + '"')

# 1b) Bind old version of above.
resp = server1.dig("hostname.bind", "TXT", "CH")
resp.check('"' + name + '"')

# 2) FQDN hostname.
resp = server2.dig("id.server", "TXT", "CH")
resp.check(t.hostname)

# 3) Explicitly disabled.
resp = server3.dig("id.server", "TXT", "CH")
resp.check(rcode="REFUSED")

# 4) Disabled.
resp = server4.dig("id.server", "TXT", "CH")
resp.check(rcode="REFUSED")

t.end()
