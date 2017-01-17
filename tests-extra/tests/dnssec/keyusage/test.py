#!/usr/bin/env python3

'''Check if dnssec keys in use are protected from being removed automatically.'''

import collections
import os
import shutil
import datetime
import time
import subprocess

from dnstest.utils import *
from dnstest.keys import Keymgr
from dnstest.test import Test

def key_set(server, zone, key_id, **new_values):
    cmd = ["zone", "key", "set", zone, key_id]
    for option, value in new_values.items():
        cmd += [option, value]
    Keymgr.run_check(server.keydir, *cmd)

t = Test()

knot = t.server("knot")
zone1 = t.zone("example.com.")
zone2 = t.zone("records.")
zones = zone1 + zone2;
t.link(zones, knot)

shutil.copytree(os.path.join(t.data_dir, "keys"), knot.keydir)

# policy parameters
key_ttl = 10
zone1_delay = 0
zone2_delay = 10
# policy
knot.dnssec(zone1).enable = True
knot.dnssec(zone2).enable = True
knot.dnssec(zone1).dnskey_ttl = key_ttl
knot.dnssec(zone2).dnskey_ttl = key_ttl
knot.dnssec(zone1).zsk_lifetime = 10
knot.dnssec(zone2).zsk_lifetime = 10
knot.dnssec(zone1).propagation_delay = zone1_delay
knot.dnssec(zone2).propagation_delay = zone2_delay
knot.dnssec(zone1).rrsig_lifetime = 10
knot.dnssec(zone2).rrsig_lifetime = 10
knot.dnssec(zone1).rrsig_refresh = 5
knot.dnssec(zone2).rrsig_refresh = 5
knot.dnssec(zone1).alg = "rsasha1-nsec3-sha1"
knot.dnssec(zone2).alg = "rsasha1-nsec3-sha1"

# parameters
zonename1 = zone1[0].name
zonename2 = zone2[0].name

KSK = "7a3500c7feac3fd99f09a208a83b97f7455fa3e0"
ACTIVE = "f3b8db9d60fb412d0363dd0c0ac2ea72dc212777"
PUBLISHED = "712d0d0d57fa0aa006b5e20cd84e23941e5f3ab2"

time = str(round(time.time()) - 10)

#ksk
key_set(knot, zonename1, KSK, publish=time, active=time)
key_set(knot, zonename2, KSK, publish=time, active=time)
#zsk - active
key_set(knot, zonename1, ACTIVE, publish=time, active=time)
key_set(knot, zonename2, ACTIVE, publish=time, active=time)
#zsk - published
key_set(knot, zonename1, PUBLISHED, publish=time)
key_set(knot, zonename2, PUBLISHED, publish=time)

# time to rollover - dnskey_ttl + propagation delay
zone1_time = key_ttl + zone1_delay
zone2_time = key_ttl + zone2_delay - zone1_time

t.start()
t.sleep(zone1_time)
# Key is used by ZONE2 - was key deleted?
if not os.path.exists(os.path.join(knot.keydir, 'keys', ACTIVE + ".pem")):
    set_err("MISSING KEY")
    check_log("ERROR: Key in use deleted")

if not os.path.exists(os.path.join(knot.keydir, 'keys', PUBLISHED + ".pem")):
    set_err("NEXT KEY")
    check_log("ERROR: Published key was deleted")

t.sleep(zone2_time)
# key is not used anymore - was key deleted?
if os.path.exists(os.path.join(knot.keydir, 'keys', ACTIVE + ".pem")):
    set_err("REDUNDANT KEY")
    check_log("ERROR: Retired key was not deleted")

if not os.path.exists(os.path.join(knot.keydir, 'keys', PUBLISHED + ".pem")):
    set_err("NEXT KEY")
    check_log("ERROR: Published key was deleted")

t.end()
