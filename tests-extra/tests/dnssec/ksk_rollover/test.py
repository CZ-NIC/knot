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
    dnskeys = server.dig("example.com", "DNSKEY", bufsize=1024)
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

child.zonefile_sync = 24 * 60 * 60

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
KSK1 = "38b3062a04178cde79f72fc1c77fbb3fb327ffc6"
KSK2 = "1cc322baeb75cecf96babba98140206bbe28a682"
ZSK1 = "a61d2dfce7bcd667cc2be53ab3d668d4a9e3c563"
ZSK2 = "246d81610c3e3e1cf99ffa1eecd95f1deee01f0e"

t.rel_sleep(0)

# note that some of these paraneters will be immediately or later modified by automated key management
child.key_set(ZONE, KSK1, created="t-2y", publish="t-2y", ready="t-1y", active="t-1y", retire="t+10y", remove="t+20y")
# KSK1's retire and remove shall be reconfigured by Knot to soon as KSK2 takes place
child.key_set(ZONE, KSK2, created="t+0", publish="t+0", ready="t+1h", active="t+10y", retire="t+11y", remove="t+12y")
child.key_set(ZONE, ZSK1, created="t-20", publish="t-20", ready="t-10", active="t-10", retire="t+15y", remove="t+20y")
# ZSK1 simply valid for all the time
child.key_set(ZONE, ZSK2, created="t-2", publish="t-2", ready="t+14y", active="t+14y", retire="t+31y", remove="t+36y")
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
