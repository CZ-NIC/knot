#!/usr/bin/env python3

"""
Check if keytag conflict is correctly handled by Knot.
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

def key_set(server, zone, key_id, **new_values):
	for option, value in new_values.items():
		check_call([params.pykeymgr_py, "-s", server.keydir, zone, key_id, option, value],
		           stdout=open(server.dir + "/key_set.out", mode="a"),
		           stderr=open(server.dir + "/key_set.err", mode="a"))

# check zone if keys are present and used for signing
def check_zone4(server, min_dnskeys, min_rrsigs, msg):
    dnskeys = server.dig("example.com", "DNSKEY")
    found_dnskeys = dnskeys.count("DNSKEY")

    soa = server.dig("mail.example.com", "A", dnssec=True)
    found_rrsigs = soa.count("RRSIG")

    check_log("RRSIGs: %d (expected min %d)" % (found_rrsigs, min_rrsigs));
    check_log("DNSKEYs: %d (expected min %d)" % (found_dnskeys, min_dnskeys));

    if found_rrsigs < min_rrsigs:
        set_err("BAD RRSIG COUNT: " + msg)
        detail_log("!RRSIGs not published and activated as expected: " + msg)

    if found_dnskeys < min_dnskeys:
        set_err("BAD DNSKEY COUNT: " + msg)
        detail_log("!DNSKEYs not published and activated as expected: " + msg)

    detail_log(SEP)

t = Test()

knot = t.server("knot")
zone = t.zone("example.com.")
t.link(zone, knot)
knot.dnssec(zone).enable = True
knot.dnssec(zone).manual = True
knot.dnssec(zone).rrsig_lifetime = 5
knot.dnssec(zone).rrsig_refresh = 2
knot.zonefile_sync = "0"

# install keys (one always enabled, one for testing)
shutil.copytree(os.path.join(t.data_dir, "keys"), knot.keydir)
knot.dnssec_import_json()

# parameters
ZONE = "example.com"
KSK = "7a3500c7feac3fd99f09a208a83b97f7455fa3e0"
ZSK1 = "712d0d0d57fa0aa006b5e20cd84e23941e5f3ab2"
ZSK2 = "301d3fc5392e83ea02312dc5bdc1a9f0b7937ddf"
ZSK3 = "6abddc73bcb46c4e6078cf764290ac315fff03f0"

key_set(knot, ZONE, KSK, publish="t-2y", active="t-1y", retire="t+1y", remove="t+2y")
key_set(knot, ZONE, ZSK1, publish="t-20", active="t-10", retire="t+15", remove="t+20")
key_set(knot, ZONE, ZSK2, publish="t+8", active="t+14", retire="t+31", remove="t+36")
key_set(knot, ZONE, ZSK3, publish="t+24", active="t+30", retire="t+1y", remove="t+2y") 

t.start()
t.sleep(4)

check_zone4(knot, 2, 1, "initial keys")

t.sleep(15)

check_zone4(knot, 2, 1, "standard rollover")

t.sleep(13)

for x in range(1, 8):
	check_zone4(knot, 2, 1, "conflicting rollover %i" % x)
	t.sleep(2)

t.end()
