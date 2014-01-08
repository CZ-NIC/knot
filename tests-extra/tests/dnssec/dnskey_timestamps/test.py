#!/usr/bin/env python3

"""
Check if DNSKEY lifetime timestamps are proccessed correctly by Knot.
"""

import collections
import os
import shutil

from dnstest.utils import *
from dnstest.test import Test

# change timestamps in DNSSEC key file
def key_settime(filename, **new_values):
    lines = open(filename).readlines()

    values = collections.OrderedDict()
    for line in lines:
        key, sep, value = line.partition(":")
        values[key.strip()] = value.strip()

    for key, value in new_values.items():
        values[key] = value

    with open(filename, "w") as keyfile:
        for key, value in values.items():
            if value is not None:
                keyfile.write("%s: %s\n" % (key, value))

# check zone if keys are present and used for signing
def check_zone(server, expect_dnskey, expect_rrsig):
    dnskeys = server.dig("example.com", "DNSKEY")
    soa = server.dig("example.com", "SOA", dnssec=True)

    found_dnskeys = dnskeys.answer_count("DNSKEY")
    found_rrsigs = soa.answer_count("RRSIG")

    expect_dnskeys = 2 if expect_dnskey else 1
    expect_rrsigs = 2 if expect_rrsig else 1

    detail_log("DNSKEYs: %d (expected %d) RRSIGs: %d (expected %d)" % (
                       found_dnskeys, expect_dnskeys, found_rrsigs, expect_rrsigs));

    if found_dnskeys != expect_dnskeys or found_rrsigs != expect_rrsigs:
        err("Expectations do not match.")
        set_err("DNSKEYs not published and activated as expected.")

t = Test()

knot = t.server("knot")
knot.dnssec_enable = True
zone = t.zone("example.com.")
t.link(zone, knot)

# install keys (one always enabled, one for testing)
shutil.copytree(os.path.join(t.data_dir, "keys"), knot.keydir)

# parameters
key_file = os.path.join(knot.keydir, "test.private")
date_past = "19700101000001"
date_future = "20400101000000"
WAIT_SIGN = 0

#
# Common cases
#

# key not published, not active
key_settime(key_file, Publish=date_future, Activate=date_future)
t.start()
t.sleep(WAIT_SIGN)
check_zone(knot, False, False)

# key published, not active
key_settime(key_file, Publish=date_past)
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, True, False)

# key published, active
key_settime(key_file, Activate=date_past)
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, True, True)

# key published, inactive
key_settime(key_file, Inactive=date_past)
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, True, False)

# key deleted, inactive
key_settime(key_file, Delete=date_past)
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, False, False)

#
# Special cases
#

# key not published, active (algorithm rotation)
key_settime(key_file, Publish=date_future, Activate=date_past, Inactive=None, Delete=None)
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, False, True)

t.end()
