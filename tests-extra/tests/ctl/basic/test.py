#!/usr/bin/env python3

'''Ctl conf and zone commands test.'''

import os

from dnstest.libknot import libknot
from dnstest.module import ModStats
from dnstest.test import Test
from dnstest.utils import *

t = Test()

knot = t.server("knot")

# Enable a global module to check the modules reuse doesn't crash the server.
knot.add_module(None, ModStats())

ctl = libknot.control.KnotCtl()

ZONE_NAME = "testzone."

t.start()

ctl.connect(os.path.join(knot.dir, "knot.sock"))

# Add new zone.
ctl.send_block(cmd="conf-begin")
resp = ctl.receive_block()

ctl.send_block(cmd="conf-set", section="zone", item="domain", data=ZONE_NAME)
resp = ctl.receive_block()

ctl.send_block(cmd="conf-set", section="zone", item="file", identifier=ZONE_NAME,
               data=os.path.join(knot.dir, ZONE_NAME + "zone"))
resp = ctl.receive_block()

ctl.send_block(cmd="conf-commit")
resp = ctl.receive_block()

ctl.send_block(cmd="conf-read", section="zone")
resp = ctl.receive_block()

isset(ZONE_NAME in resp['zone'], "zone configured")
isset("file" in resp['zone'][ZONE_NAME], "zone.file configured")

# Fill the zone content.
ctl.send_block(cmd="zone-begin")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-set", zone=ZONE_NAME, owner="@", ttl="3600", rtype="SOA",
               data="a. b. 1 2 3 4 5")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-set", zone=ZONE_NAME, owner="@", ttl="3600", rtype="A",
               data="192.168.0.1")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-get", zone=ZONE_NAME, owner="@")
resp = ctl.receive_block()

isset("A" in resp[ZONE_NAME][ZONE_NAME], "txn A presence")
isset("192.168.0.1" in resp[ZONE_NAME][ZONE_NAME]["A"]["data"], "txn A rdata")

ctl.send_block(cmd="zone-set", zone=ZONE_NAME, owner="utqvuhu2blk3dhmrr5t1hd9vteohqt0a." + ZONE_NAME,
               ttl="3600", rtype="NSEC3", data="1 0 10 - dks9i43rb5utfau23saq45qmv6stlthu A RRSIG")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-get", zone=ZONE_NAME, owner="utqvuhu2blk3dhmrr5t1hd9vteohqt0a." + ZONE_NAME)
resp = ctl.receive_block()

isset("NSEC3" in resp[ZONE_NAME]["utqvuhu2blk3dhmrr5t1hd9vteohqt0a." + ZONE_NAME], "txn NSEC3 presence")
isset("1 0 10 - dks9i43rb5utfau23saq45qmv6stlthu A RRSIG" in \
      resp[ZONE_NAME]["utqvuhu2blk3dhmrr5t1hd9vteohqt0a." + ZONE_NAME]["NSEC3"]["data"], "txn NSEC3 rdata")

ctl.send_block(cmd="zone-commit")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-read", zone=ZONE_NAME)
resp = ctl.receive_block()

isset(ZONE_NAME in resp, "zone content")
isset("SOA" in resp[ZONE_NAME][ZONE_NAME], "zone SOA presence")
isset("3600" in resp[ZONE_NAME][ZONE_NAME]["SOA"]["ttl"], "zone SOA ttl")
isset("a. b. 1 2 3 4 5" in resp[ZONE_NAME][ZONE_NAME]["SOA"]["data"], "zone SOA rdata")
isset("A" in resp[ZONE_NAME][ZONE_NAME], "zone A presence")
isset("3600" in resp[ZONE_NAME][ZONE_NAME]["A"]["ttl"], "zone A ttl")
isset("192.168.0.1" in resp[ZONE_NAME][ZONE_NAME]["A"]["data"], "zone A rdata")
isset("NSEC3" in resp[ZONE_NAME]["utqvuhu2blk3dhmrr5t1hd9vteohqt0a."+ZONE_NAME], "zone NSEC3 presence")
isset("1 0 10 - dks9i43rb5utfau23saq45qmv6stlthu A RRSIG" in resp[ZONE_NAME]["utqvuhu2blk3dhmrr5t1hd9vteohqt0a."+ZONE_NAME]["NSEC3"]["data"], "zone NSEC3 rdata")

# Remove NSEC3 node.

ctl.send_block(cmd="zone-begin")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-unset", zone=ZONE_NAME, owner="utqvuhu2blk3dhmrr5t1hd9vteohqt0a")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-commit")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-read", zone=ZONE_NAME)
resp = ctl.receive_block()

if "utqvuhu2blk3dhmrr5t1hd9vteohqt0a."+ZONE_NAME in resp[ZONE_NAME]:
    set_err("zone NSEC3 removal")

ctl.send(libknot.control.KnotCtlType.END)
ctl.close()

# Check the zone.
resp = knot.dig(ZONE_NAME, "SOA")
resp.check(rcode="NOERROR")

ctl.connect(os.path.join(knot.dir, "knot.sock"))

# Abort remove SOA.
ctl.send_block(cmd="zone-begin")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-unset", zone=ZONE_NAME, owner="@", rtype="SOA")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-abort")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-read")
resp = ctl.receive_block()

isset(ZONE_NAME in resp, "zone content")
isset("SOA" in resp[ZONE_NAME][ZONE_NAME], "zone SOA presence")

# Commit removed A.
ctl.send_block(cmd="zone-begin")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-unset", zone=ZONE_NAME, owner="@", rtype="A")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-commit")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-read")
resp = ctl.receive_block()

isset(ZONE_NAME in resp, "zone content")
isset("A" not in resp[ZONE_NAME][ZONE_NAME], "zone A presence")

# Test removing whole rrset and whole node.

ctl.send_block(cmd="zone-begin")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-set", zone=ZONE_NAME, owner=ZONE_NAME, ttl="3600", rtype="TXT",
               data="text")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-set", zone=ZONE_NAME, owner="rrset", ttl="3600", rtype="A",
               data="192.168.0.2")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-set", zone=ZONE_NAME, owner="rrset", ttl="3600", rtype="A",
               data="192.168.0.3")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-set", zone=ZONE_NAME, owner="rrset", ttl="3600", rtype="AAAA",
               data="3::4")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-set", zone=ZONE_NAME, owner="node", ttl="3600", rtype="A",
               data="192.168.0.2")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-set", zone=ZONE_NAME, owner="node", ttl="3600", rtype="AAAA",
               data="1::2")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-commit")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-read", zone=ZONE_NAME)
resp = ctl.receive_block()

isset("\"text\"" in resp[ZONE_NAME][ZONE_NAME]["TXT"]["data"], "rrset TXT presence")
isset("A" in resp[ZONE_NAME]["rrset." + ZONE_NAME], "rrset A presence")
isset("192.168.0.2" in resp[ZONE_NAME]["rrset." + ZONE_NAME]["A"]["data"], "rrset A rdata 1")
isset("192.168.0.3" in resp[ZONE_NAME]["rrset." + ZONE_NAME]["A"]["data"], "rrset A rdata 2")
isset("A" in resp[ZONE_NAME]["node." + ZONE_NAME], "node A presence")
isset("AAAA" in resp[ZONE_NAME]["node." + ZONE_NAME], "node AAAA presence")

ctl.send_block(cmd="zone-begin")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-unset", zone=ZONE_NAME, owner=ZONE_NAME, rtype="SOA")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-unset", zone=ZONE_NAME, owner=ZONE_NAME)
resp = ctl.receive_block()

ctl.send_block(cmd="zone-unset", zone=ZONE_NAME, owner="rrset", rtype="A")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-unset", zone=ZONE_NAME, owner="node")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-commit")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-read", zone=ZONE_NAME)
resp = ctl.receive_block()

isset("SOA" in resp[ZONE_NAME][ZONE_NAME], "rrset SOA presence in apex") # SOA must be preserved
isset("TXT" not in resp[ZONE_NAME][ZONE_NAME], "rrset TXT absence in apex")
isset("A" not in resp[ZONE_NAME]["rrset." + ZONE_NAME], "rrset A absence")
isset(("node." + ZONE_NAME) not in resp[ZONE_NAME], "node absence")

# Check for proper handling of upper letter-case in the owner name.
ctl.send_block(cmd="zone-begin")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-set", zone=ZONE_NAME, owner="lETter", ttl="3600", rtype="TXT", data="text")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-commit")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-read", zone=ZONE_NAME, owner="letter")
resp = ctl.receive_block()
isset("letter." + ZONE_NAME in resp[ZONE_NAME], "lower-cased and inserted node lETter")

ctl.send_block(cmd="zone-begin")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-unset", zone=ZONE_NAME, owner="lETter")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-commit")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-read", zone=ZONE_NAME)
resp = ctl.receive_block()
isset("letter." + ZONE_NAME not in resp[ZONE_NAME], "lower-cased and removed node lETter")

# Purge the zone data.
ctl.send_block(cmd="zone-purge", flags="B")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-read", section="test-zone")
resp = ctl.receive_block()

isset(ZONE_NAME not in resp, "zone content")

resp = knot.dig(ZONE_NAME, "SOA")
resp.check(rcode="SERVFAIL")

# Abort removed zone.
ctl.send_block(cmd="conf-begin")
resp = ctl.receive_block()

ctl.send_block(cmd="conf-unset", section="zone", item="domain", data=ZONE_NAME)
resp = ctl.receive_block()

ctl.send_block(cmd="conf-abort")
resp = ctl.receive_block()

ctl.send_block(cmd="conf-read", section="zone")
resp = ctl.receive_block()

isset(ZONE_NAME in resp["zone"], "zone configured")

# Commit removed zone.
ctl.send_block(cmd="conf-begin")
resp = ctl.receive_block()

ctl.send_block(cmd="conf-unset", section="zone", item="domain", data=ZONE_NAME)
resp = ctl.receive_block()

ctl.send_block(cmd="conf-commit")
resp = ctl.receive_block()

ctl.send_block(cmd="conf-read", section="zone")
resp = ctl.receive_block()

isset("zone" not in resp, "zone not configured")

ctl.send(libknot.control.KnotCtlType.END)
ctl.close()

resp = knot.dig(ZONE_NAME, "SOA")
resp.check(rcode="REFUSED")

t.end()
