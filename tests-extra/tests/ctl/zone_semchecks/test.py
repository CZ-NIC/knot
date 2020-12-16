#!/usr/bin/env python3

'''Test for zone semantic checks during zone commit.'''

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

ctl.send_block(cmd="conf-commit")
resp = ctl.receive_block()

# Try to create initial zone contents with a semantic error.
ctl.send_block(cmd="zone-begin", zone=ZONE_NAME)
resp = ctl.receive_block()

ctl.send_block(cmd="zone-set", zone=ZONE_NAME, owner="@", ttl="3600", rtype="SOA",
               data="a. b. 1 2 3 4 5")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-set", zone=ZONE_NAME, owner="@", ttl="600", rtype="A",
               data="192.168.0.1")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-set", zone=ZONE_NAME, owner="@", ttl="3600", rtype="CNAME",
               data="example.com.")
resp = ctl.receive_block()

try:
    ctl.send_block(cmd="zone-commit", zone=ZONE_NAME)
    resp = ctl.receive_block()
except libknot.control.KnotCtlError as e:
    isset("semantic check" in e.message.lower(), "expected error")
else:
    set_err("SEMANTIC CHECK NOT APPLIED")

# Fix the semantic error and continue.
ctl.send_block(cmd="zone-unset", zone=ZONE_NAME, owner="@", rtype="CNAME")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-commit", zone=ZONE_NAME)
resp = ctl.receive_block()

# Check the resulting zone contents.
ctl.send_block(cmd="zone-read", zone=ZONE_NAME)
resp = ctl.receive_block()

isset(ZONE_NAME in resp, "zone contents")
isset("SOA" in resp[ZONE_NAME][ZONE_NAME], "zone SOA presence")
isset("3600" in resp[ZONE_NAME][ZONE_NAME]["SOA"]["ttl"], "zone SOA ttl")
isset("a. b. 1 2 3 4 5" in resp[ZONE_NAME][ZONE_NAME]["SOA"]["data"], "zone SOA rdata")
isset("A" in resp[ZONE_NAME][ZONE_NAME], "zone A presence")
isset("600" in resp[ZONE_NAME][ZONE_NAME]["A"]["ttl"], "zone A ttl")
isset("192.168.0.1" in resp[ZONE_NAME][ZONE_NAME]["A"]["data"], "zone A rdata")
isset("CNAME" not in resp[ZONE_NAME][ZONE_NAME], "zone CNAME absence")

# Try to introduce a semantic error to existing zone contents.
ctl.send_block(cmd="zone-begin", zone=ZONE_NAME)
resp = ctl.receive_block()

ctl.send_block(cmd="zone-set", zone=ZONE_NAME, owner="@", ttl="3600", rtype="CNAME",
               data="example.com.")
resp = ctl.receive_block()

try:
    ctl.send_block(cmd="zone-commit", zone=ZONE_NAME)
    resp = ctl.receive_block()
except libknot.control.KnotCtlError as e:
    isset("semantic check" in e.message.lower(), "expected error")
else:
    set_err("SEMANTIC CHECK NOT APPLIED")

# Fix the semantic error and continue.
ctl.send_block(cmd="zone-unset", zone=ZONE_NAME, owner="@", rtype="CNAME")
resp = ctl.receive_block()

ctl.send_block(cmd="zone-commit", zone=ZONE_NAME)
resp = ctl.receive_block()

# Check the resulting zone contents.
ctl.send_block(cmd="zone-read", zone=ZONE_NAME)
resp = ctl.receive_block()

isset(ZONE_NAME in resp, "zone contents")
isset("SOA" in resp[ZONE_NAME][ZONE_NAME], "zone SOA presence")
isset("A" in resp[ZONE_NAME][ZONE_NAME], "zone A presence")
isset("CNAME" not in resp[ZONE_NAME][ZONE_NAME], "zone CNAME absence")

# Cleanup.
ctl.send(libknot.control.KnotCtlType.END)
ctl.close()

t.end()
