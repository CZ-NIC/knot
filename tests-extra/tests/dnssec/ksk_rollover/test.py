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

# check zone if keys are present and used for signing
def check_zone5(server, min_dnskeys, min_rrsigs, min_cdnskeys, msg):
    dnskeys = server.dig("example.com", "DNSKEY")
    found_dnskeys = dnskeys.count("DNSKEY")

    soa = server.dig("example.com", "DNSKEY", dnssec=True)
    found_rrsigs = soa.count("RRSIG")
    
    cdnskey = server.dig("example.com", "CDNSKEY")
    found_cdnskeys = cdnskey.count("CDNSKEY")

    check_log("RRSIGs: %d (expected %d)" % (found_rrsigs, min_rrsigs));
    check_log("DNSKEYs: %d (expected %d)" % (found_dnskeys, min_dnskeys));
    check_log("CDNSKEYs: %d (expected %d)" % (found_cdnskeys, min_cdnskeys));

    if found_rrsigs != min_rrsigs:
        set_err("BAD RRSIG COUNT: " + msg)
        detail_log("!RRSIGs not published and activated as expected: " + msg)

    if found_dnskeys != min_dnskeys:
        set_err("BAD DNSKEY COUNT: " + msg)
        detail_log("!DNSKEYs not published and activated as expected: " + msg)

    if found_cdnskeys != min_cdnskeys:
        set_err("BAD CDNSKEY COUNT: " + msg)
        detail_log("!CDNSKEYs not published and activated as expected: " + msg)
        
    detail_log(SEP)

t = Test()

parent = t.server("knot")
parent_zone = t.zone("com.", storage=".")
t.link(parent_zone, parent)

child = t.server("knot")
child_zone = t.zone("example.com.")
t.link(child_zone, child)

child.dnssec(child_zone).enable = True
child.dnssec(child_zone).manual = False
child.dnssec(child_zone).zsk_lifetime = 99999
child.dnssec(child_zone).ksk_lifetime = 300 # this can be possibly left also infinity
child.dnssec(child_zone).propagation_delay = 17
child.dnssec(child_zone).ksk_submittion_check = [ parent ]
child.dnssec(child_zone).ksk_submittion_check_interval = 2

# install KASP db (one always enabled, one for testing)
shutil.copytree(os.path.join(t.data_dir, "keys"), child.keydir)

# parameters
ZONE = "example.com."
KSK1 = "7a3500c7feac3fd99f09a208a83b97f7455fa3e0"
KSK2 = "7e7492f7dcaf4d819a29eb30ad80c04f830d76cf"
ZSK1 = "6abddc73bcb46c4e6078cf764290ac315fff03f0"
ZSK2 = "301d3fc5392e83ea02312dc5bdc1a9f0b7937ddf"

t.rel_sleep(0)

# note that some of these paraneters will be immediately or later modified by automated key management
child.key_set(ZONE, KSK1, publish="t-2y", ready="t-1y", active="t-1y", retire="t+10y", remove="t+20y")
# KSK1's retire and remove shall be reconfigured by Knot to soon as KSK2 takes place
child.key_set(ZONE, KSK2, publish="t+0", ready="t+1h", active="t+10y", retire="t+11y", remove="t+12y")
child.key_set(ZONE, ZSK1, publish="t-20", ready="t-10", active="t-10", retire="t+15y", remove="t+20y")
# ZSK1 simply valid for all the time
child.key_set(ZONE, ZSK2, publish="t-2", ready="t+14y", active="t+14y", retire="t+31y", remove="t+36y")
# ZSK2 only reason: prevents Knot from publishing another ZSK

t.start()
child.zone_wait(child_zone)

check_zone5(child, 4, 1, 0, "only first KSK")

t.rel_sleep(19)

check_zone5(child, 4, 2, 1, "new KSK ready")

parent.update_zonefile(parent_zone, version=1)
parent.reload()
parent.zone_wait(parent_zone)

t.sleep(21)

check_zone5(child, 2, 1, 0, "old KSK retired")

t.end()
