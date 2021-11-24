#!/usr/bin/env python3

"""
Check if DNSKEY lifetime timestamps are processed correctly by Knot.
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
def check_zone(server, expect_dnskey, expect_rrsig, msg):
    dnskeys = server.dig("example.com", "DNSKEY")
    soa = server.dig("example.com", "SOA", dnssec=True)

    found_dnskeys = dnskeys.count("DNSKEY")
    found_rrsigs = soa.count("RRSIG")

    expect_dnskeys = 3 if expect_dnskey else 2
    expect_rrsigs = 2 if expect_rrsig else 1

    check_log("DNSKEYs: %d (expected %d) RRSIGs: %d (expected %d)" %
              (found_dnskeys, expect_dnskeys, found_rrsigs, expect_rrsigs));

    if found_dnskeys != expect_dnskeys or found_rrsigs != expect_rrsigs:
        set_err("BAD DNSKEY: " + msg)
        detail_log("!DNSKEYs not published and activated as expected: " + msg)

    detail_log(SEP)

t = Test()

knot = t.server("knot")
zone = t.zone("example.com.")
t.link(zone, knot)
knot.dnssec(zone).enable = True
knot.dnssec(zone).manual = True

# parameters
ZONE = "example.com."
WAIT_SIGN = 2

# needed for keymgr
knot.gen_confile()

# generate initial keys (one always enabled, one for testing)
knot.key_gen(ZONE, ksk="true", created="+0", publish="+0", ready="+0", active="+0", retire="+1d", remove="+1d")
knot.key_gen(ZONE, ksk="false", created="+0", publish="+0", ready="+0", active="+0", retire="+1d", remove="+1d")

#
# Common cases
#

check_log("Common cases")

# key not published, not active
KEYID = knot.key_gen(ZONE, ksk="false", publish="+10y", ready="+10y", active="+10y", retire="+11y", remove="+12y")
t.start()
t.sleep(WAIT_SIGN)
check_zone(knot, False, False, "not published, not active")

# key published, not active
knot.key_set(ZONE, KEYID, publish="-10y")
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, True, False, "published, not active")

# key published, active
knot.key_set(ZONE, KEYID, active="-10y")
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, True, True, "published, active")

# key published, inactive
knot.key_set(ZONE, KEYID, retire="-10y")
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, True, False, "published, inactive")

# key deleted, inactive
knot.key_set(ZONE, KEYID, remove="-10y")
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, False, False, "deleted, inactive")

# key not published, active (algorithm rotation)
knot.key_set(ZONE, KEYID, publish="+10y", ready="+10y", active="+10y", pre_active="-10y", retire="0", remove="0")
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, False, True, "not published, active")

#
# Test DNSSEC key event execution
#

check_log("Planned events")

# key about to be published
event_in = 7
knot.key_set(ZONE, KEYID, publish=("+%d" % event_in), ready="+10y", active="+10y", pre_active="0", retire="0", remove="0")
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, False, False, "to be published - pre")
t.sleep(event_in)
check_zone(knot, True, False, "to be published - post")

# key about to be activated
knot.key_set(ZONE, KEYID, publish="-10y", ready=("+%d" % event_in), active=("+%d" % event_in), retire="0", remove="0")
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, True, False, "to be activated - pre")
t.sleep(event_in)
check_zone(knot, True, True, "to be activated - post")

#key about to be inactivated
knot.key_set(ZONE, KEYID, publish="-10y", ready="-10y", active="-10y", retire=("+%d" % event_in), remove="0")
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, True, True, "to be inactivated - pre")
t.sleep(event_in)
check_zone(knot, True, False, "to be inactivated - post")

#key about to be deleted
knot.key_set(ZONE, KEYID, publish="-10y", ready="-10y", active="-10y", retire="-10y", remove=("+%d" % event_in))
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, True, False, "to be deleted - pre")
t.sleep(event_in)
check_zone(knot, False, False, "to be deleted - post")

t.end()
