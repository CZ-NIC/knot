#!/usr/bin/env python3

''' Check 'dnsproxy' query module functionality. '''

from dnstest.test import Test
from dnstest.module import ModDnsproxy

t = Test(stress=False)

ModDnsproxy.check()

# Initialize server configuration
local_zone = t.zone("test", storage=".", file_name="test.local_zone")
remote_zone1 = t.zone("test", storage=".", file_name="test.remote_zone")
remote_zone2 = t.zone("example.com.")

local1 = t.server("knot")
t.link(local_zone, local1)

local2 = t.server("knot")
t.link(local_zone, local2)

remote = t.server("knot")
t.link(remote_zone1, remote)
t.link(remote_zone2, remote)

t.start()

# Only after successful start the remote address is known!
local1.add_module(None, ModDnsproxy(remote.addr, remote.port))
local1.gen_confile()
local1.reload()
local2.add_module(None, ModDnsproxy(remote.addr, remote.port, True))
local2.gen_confile()
local2.reload()

# Local1

# Local OK response.
resp = local1.dig("dns1.test", "A")
resp.check(rcode="NOERROR", flags="AA", rdata="192.0.2.1")

# Local NOK response, not forwarded.
resp = local1.dig("extra.test", "A")
resp.check(rcode="NXDOMAIN", flags="AA")

# Remote OK response.
resp = local1.dig("example.com", "SOA")
resp.check(rcode="NOERROR", flags="AA")

# Remote NOK response, not existing owner.
resp = local1.dig("extra.example.com", "A")
resp.check(rcode="NXDOMAIN", flags="AA")

# Remote NOK response, not existing zone.
resp = local1.dig("unknown", "SOA")
resp.check(rcode="REFUSED", noflags="AA")

# Local2

# Local OK response.
resp = local2.dig("dns1.test", "A")
resp.check(rcode="NOERROR", flags="AA", rdata="192.0.2.1")

# Local NOK response, but forwarded OK.
resp = local2.dig("extra.test", "A")
resp.check(rcode="NOERROR", flags="AA", rdata="1.1.1.1")

# Remote OK response.
resp = local2.dig("example.com", "SOA")
resp.check(rcode="NOERROR", flags="AA")

# Remote NOK response, not existing owner.
resp = local2.dig("extra.example.com", "A")
resp.check(rcode="NXDOMAIN", flags="AA")

# Remote NOK response, not existing zone.
resp = local2.dig("unknown", "SOA")
resp.check(rcode="REFUSED", noflags="AA")

t.end()
