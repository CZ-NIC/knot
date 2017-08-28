#!/usr/bin/env python3

"""
Basic check of automatic KSK rollover scenario.
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
child.dnssec(child_zone).ksk_sbm_check = [ parent ]
child.dnssec(child_zone).ksk_sbm_check_interval = 2

# parameters
ZONE = "example.com."

# note that some of these paraneters will be immediately or later modified by automated key management
KSK1 = child.key_gen(ZONE, ksk="true", created="-2y", publish="-2y", ready="-1y", active="-1y", retire="+10y", remove="+20y")
# KSK1's retire and remove shall be reconfigured by Knot to soon as KSK2 takes place
KSK2 = child.key_gen(ZONE, ksk="true", created="+0", publish="+0", ready="+1h", active="+10y", retire="+11y", remove="+12y")
ZSK1 = child.key_gen(ZONE, ksk="false", created="-20", publish="-20", ready="-10", active="-10", retire="+15y", remove="+20y")
# ZSK1 simply valid for all the time
ZSK2 = child.key_gen(ZONE, ksk="false", created="-2", publish="-2", ready="+14y", active="+14y", retire="+31y", remove="+36y")
# ZSK2 only reason: prevents Knot from publishing another ZSK

t.start()
child.zone_wait(child_zone)

check_zone5(child, 4, 1, 0, "only first KSK")

while child.dig(ZONE, "CDS").count("CDS") < 1:
  t.sleep(1)

check_zone5(child, 4, 2, 1, "new KSK ready")

cds = child.dig(ZONE, "CDS")
cds_rdata = cds.resp.answer[0].to_rdataset()[0].to_text()
up = parent.update(parent_zone)
up.add(ZONE, 3600, "DS", cds_rdata)
up.send("NOERROR")

t.sleep(23)

check_zone5(child, 2, 1, 0, "old KSK retired")

t.end()
