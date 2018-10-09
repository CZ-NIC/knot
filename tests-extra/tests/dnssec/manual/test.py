#!/usr/bin/env python3

"""
Check if zone gets re-signed when keys change in manual policy.
"""

import collections
import os
import shutil
import datetime
import subprocess
from subprocess import check_call

from dnstest.utils import *
from dnstest.keys import Keymgr
from dnstest.test import Test

# check zone if keys are present and used for signing
def check_zone4(server, min_dnskeys, min_rrsigs, msg):
    dnskeys = server.dig("example.com", "DNSKEY")
    found_dnskeys = dnskeys.count("DNSKEY")

    soa = server.dig("mail.example.com", "A", dnssec=True)
    found_rrsigs = soa.count("RRSIG")

    check_log("RRSIGs: %d (expected %d)" % (found_rrsigs, min_rrsigs));
    check_log("DNSKEYs: %d (expected %d)" % (found_dnskeys, min_dnskeys));

    if found_rrsigs != min_rrsigs:
        set_err("BAD RRSIG COUNT: " + msg)
        detail_log("!RRSIGs not published and activated as expected: " + msg)

    if found_dnskeys != min_dnskeys:
        set_err("BAD DNSKEY COUNT: " + msg)
        detail_log("!DNSKEYs not published and activated as expected: " + msg)

    detail_log(SEP)

t = Test()

knot = t.server("knot")
zone = t.zone("example.com.")
t.link(zone, knot)
knot.dnssec(zone).enable = True
knot.dnssec(zone).manual = True
knot.dnssec(zone).rrsig_lifetime = 5000
knot.dnssec(zone).rrsig_refresh = 2
knot.zonefile_sync = "0"
knot.port = 1328
knot.gen_confile()

# parameters
ZONE = "example.com."

knot.key_gen(ZONE, ksk="yes", publish="-2y", ready="-1y", active="-1y", retire="+1y", remove="+2y")
knot.key_gen(ZONE, ksk="no", publish="-20", active="-10", retire="+1y", remove="+2y")
knot.key_gen(ZONE, ksk="no", publish="+8", active="+8", retire="+31", remove="+36")

t.start()

check_zone4(knot, 2, 1, "initial keys")

t.sleep(6)

check_zone4(knot, 3, 2, "active key")

t.end()
