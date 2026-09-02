#!/usr/bin/env python3

import subprocess
from dnstest.test import Test
from dnstest.keys import Tsig
from dnstest.utils import *

KEY = "audit-key"
ZONE = "example.com"
OWNER = "tsig-test.example.com"
ADDRESS = "123.111.123.111"

t = Test(address=4, tsig=Tsig(KEY))

knot = t.server("knot")
zone = t.zone(ZONE)
t.link(zone, knot, ddns=True)

t.start()

knot.zone_wait(zone)

result = subprocess.run(
    ["tests/tsig/bad_mac_len/data/poc.py",
    "--host", str(knot.addr), "--port", str(knot.port), "--zone", str(ZONE),
    "--owner", str(OWNER), "--address", str(ADDRESS)],
    capture_output=True, text=True
)
detail_log(result.stdout + result.stderr)

serr = str(result.stderr).strip()
if serr != "" and serr != "no candidate selected an UPDATE-authorized TSIG key":
    set_err("POC FAILED")

resp = knot.dig(OWNER, "A")
resp.check_record(nordata=ADDRESS)

t.end()
