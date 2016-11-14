#!/usr/bin/env python3

'''Ctl conf and zone commands test.'''

import os

from dnstest.libknot import libknot
from dnstest.test import Test
from dnstest.utils import *

t = Test()

knot = t.server("knot")

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

# Purge the zone data.
ctl.send_block(cmd="zone-purge")
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
