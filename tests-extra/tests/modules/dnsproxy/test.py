#!/usr/bin/env python3

''' Check 'dnsproxy' query module functionality. '''

from dnstest.test import Test
from dnstest.module import ModDnsproxy
import dnstest.keys

t = Test(tsig=False)

ModDnsproxy.check()

# Initialize server configuration
zone_common1 = t.zone("test", storage=".", file_name="test.local_zone")
zone_common2 = t.zone("test", storage=".", file_name="test.remote_zone")
zone_local = t.zone_rnd(1)
zone_remote = t.zone_rnd(1)

key1 = dnstest.keys.Tsig(name="key1", alg="hmac-sha1", key="Zm9v")
local = t.server("knot", tsig=key1)
t.link(zone_common1, local)
t.link(zone_local, local)

key2 = dnstest.keys.Tsig(name="key2", alg="hmac-sha1", key="YmFy")
remote = t.server("knot", tsig=key2)
t.link(zone_common2, remote)
t.link(zone_remote, remote)

def fallback_checks(server, zone_local, zone_remote):
    # Local preferred OK, try with local TSIG.
    resp = server.dig("dns1.test", "A", tsig=key1)
    resp.check(rcode="NOERROR", flags="AA", rdata="192.0.2.1", nordata="192.0.2.2")

    # Local record OK.
    resp = server.dig("local.test", "A")
    resp.check(rcode="NOERROR", flags="AA", rdata="1.1.1.1")

    # Local OK.
    resp = server.dig(zone_local.name, "SOA")
    resp.check(rcode="NOERROR", flags="AA")

    # Remote OK, TSIG not forwarded if fallback.
    resp = server.dig(zone_remote.name, "SOA", tsig=key1)
    resp.check(rcode="NOERROR", flags="AA")

    # Remote NOK, not existing zone.
    resp = server.dig("z-o-n-e.", "SOA")
    resp.check(rcode="REFUSED", noflags="AA")

    # Local XFR OK.
    resp = server.dig("test", "AXFR", tsig=key1)
    resp.check_xfr(rcode="NOERROR")

    # Remote XFR NOK, no TSIG
    resp = server.dig(zone_remote.name, "AXFR")
    resp.check_xfr(rcode="NOTAUTH")

t.start()

remote.zone_wait(zone_common2)

### No fallback

# Only after successful start the remote address is known!
local.add_module(None, ModDnsproxy(remote.addr, remote.port, fallback=False))
local.gen_confile()
local.reload()

# Remote OK, try with remote TSIG.
resp = local.dig("dns1.test", "A", tsig=key2)
resp.check(rcode="NOERROR", flags="AA", rdata="192.0.2.2", nordata="192.0.2.1")

# Remote XFR OK.
resp = local.dig("test", "AXFR", tsig=key2)
resp.check_xfr(rcode="NOERROR")

# Local record NOK.
resp = local.dig("local.test", "A")
resp.check(rcode="NXDOMAIN", flags="AA")

# Remote record OK.
resp = local.dig("remote.test", "A")
resp.check(rcode="NOERROR", flags="AA", rdata="1.1.1.2")

# Local NOK, unknown zone.
resp = local.dig(zone_local[0].name, "SOA")
resp.check(rcode="REFUSED", noflags="AA")

# Remote OK.
resp = local.dig(zone_remote[0].name, "SOA")
resp.check(rcode="NOERROR", flags="AA")

# Remote NOK, not existing owner.
resp = local.dig("u-n-k-n-o-w-n." + zone_remote[0].name, "A")
resp.check(rcode="NXDOMAIN", flags="AA")

# Remote NOK, unknown zone.
resp = local.dig("z-o-n-e.", "SOA")
resp.check(rcode="REFUSED", noflags="AA")

### Fallback, no nxdomain

local.clear_modules(None)
local.add_module(None, ModDnsproxy(remote.addr, remote.port, fallback=True, nxdomain=False))
local.gen_confile()
local.reload()

fallback_checks(local, zone_local[0], zone_remote[0])

# Local NOK, not forwarded.
resp = local.dig("remote.test", "A")
resp.check(rcode="NXDOMAIN", flags="AA")

### Fallback, nxdomain

local.clear_modules(None)
local.add_module(None, ModDnsproxy(remote.addr, remote.port, fallback=True, nxdomain=True))
local.gen_confile()
local.reload()

fallback_checks(local, zone_local[0], zone_remote[0])

# Local NOK, but forwarded OK.
resp = local.dig("remote.test", "A")
resp.check(rcode="NOERROR", flags="AA", rdata="1.1.1.2")

### Per zone, fallback

local.clear_modules(None)
local.add_module(zone_common1[0], ModDnsproxy(remote.addr, remote.port, fallback=False))
local.gen_confile()
local.reload()

# Remote OK.
resp = local.dig("dns1.test", "A")
resp.check(rcode="NOERROR", flags="AA", rdata="192.0.2.2", nordata="192.0.2.1")

# Remote NOK, not forwarded.
resp = local.dig(zone_remote[0].name, "SOA")
resp.check(rcode="REFUSED", noflags="AA")

t.end()
