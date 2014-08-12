#!/usr/bin/env python3

"""
Check if DNSKEY lifetime timestamps are proccessed correctly by Knot.
"""

import collections
import os
import shutil
import datetime

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

# return date 'offset' seconds in future
def date_offset(offset):
    delta = datetime.timedelta(seconds = offset)
    current_time = datetime.datetime.utcnow()
    future_time = current_time + delta
    return datetime.datetime.strftime(future_time, "%Y%m%d%H%M%S")

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
WAIT_SIGN = 2

#
# Common cases
#

check_log("Common cases")

# key not published, not active
key_settime(key_file, Publish=date_future, Activate=date_future)
t.start()
t.sleep(WAIT_SIGN)
check_zone(knot, False, False, "not published, not active")

# key published, not active
key_settime(key_file, Publish=date_past)
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, True, False, "published, not active")

# key published, active
key_settime(key_file, Activate=date_past)
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, True, True, "published, active")

# key published, inactive
key_settime(key_file, Inactive=date_past)
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, True, False, "published, inactive")

# key deleted, inactive
key_settime(key_file, Delete=date_past)
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, False, False, "deleted, inactive")

# key not published, active (algorithm rotation)
key_settime(key_file, Publish=date_future, Activate=date_past, Inactive=None, Delete=None)
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, False, True, "not published, active")

#
# Test DNSSEC key event execution
#

check_log("Planned events")

# key about to be published
event_in = 5
key_settime(key_file, Publish=date_offset(event_in), Activate=date_future, Inactive=None, Delete=None)
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, False, False, "to be published - pre")
t.sleep(event_in)
check_zone(knot, True, False, "to be published - post")

# key about to be activated
key_settime(key_file, Publish=date_past, Activate=date_offset(event_in), Inactive=None, Delete=None)
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, True, False, "to be activated - pre")
t.sleep(event_in)
check_zone(knot, True, True, "to be activated - post")

#key about to be inactivated
key_settime(key_file, Publish=date_past, Activate=date_past, Inactive=date_offset(event_in), Delete=None)
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, True, True, "to be inactivated - pre")
t.sleep(event_in)
check_zone(knot, True, False, "to be inactivated - post")

#key about to be deleted
key_settime(key_file, Publish=date_past, Activate=date_past, Inactive=date_past, Delete=date_offset(event_in))
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, True, False, "to be deleted - pre")
t.sleep(event_in)
check_zone(knot, False, False, "to be deleted - post")

t.end()
