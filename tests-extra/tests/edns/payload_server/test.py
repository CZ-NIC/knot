#!/usr/bin/env python3

'''Test for EDNS0 UDP payload size limiting with respect to IP family'''

from dnstest.test import Test

t = Test(tsig=False)

server4 = t.server("knot", address=4)
server6 = t.server("knot", address=6)
zone = t.zone("flags.")

# Set common payload limit.
server4.udp_max_payload = 1220
server6.udp_max_payload = 1220

t.link(zone, server4)
t.link(zone, server6)

t.start()

# Check common limit if 1220 fits and 1221 does not.
resp = server4.dig("1220resp.flags", "TXT", udp=True, bufsize=4096)
resp.check(noflags="TC")

resp = server4.dig("1221resp.flags", "TXT", udp=True, bufsize=4096)
resp.check(flags="TC")

resp = server6.dig("1220resp.flags", "TXT", udp=True, bufsize=4096)
resp.check(noflags="TC")

resp = server6.dig("1221resp.flags", "TXT", udp=True, bufsize=4096)
resp.check(flags="TC")

# Set IP family specific limit.
server4.udp_max_payload_ipv4 = 1220
server4.udp_max_payload_ipv6 = 1221 # Should not affect IPv4
server4.udp_max_payload      = 1221 # Should not override IPv4 specific

server6.udp_max_payload_ipv6 = 1220
server6.udp_max_payload_ipv4 = 1221 # Should not affect IPv6
server6.udp_max_payload      = 1221 # Should not override IPv6 specific

server4.gen_confile()
server4.reload()

server6.gen_confile()
server6.reload()

# Check IP specific limit.
resp = server4.dig("1220resp.flags", "TXT", udp=True, bufsize=4096)
resp.check(noflags="TC")

resp = server4.dig("1221resp.flags", "TXT", udp=True, bufsize=4096)
resp.check(flags="TC")

resp = server6.dig("1220resp.flags", "TXT", udp=True, bufsize=4096)
resp.check(noflags="TC")

resp = server6.dig("1221resp.flags", "TXT", udp=True, bufsize=4096)
resp.check(flags="TC")

t.end()
