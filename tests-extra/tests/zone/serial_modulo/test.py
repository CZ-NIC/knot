#!/usr/bin/env python3

"""
Test of serial modulo.
"""

import random
from dnstest.utils import *
from dnstest.test import Test

SCENARIO = random.choice(["xfr-ddns", "ddns", "reload", "restart", "ddns-restart"])
MODULO_A = 3
MODULO_B = 7

def check_serial(serial, modulo_a, msg):
    if serial % MODULO_B != modulo_a:
        set_err("WRONG MODULO " + msg)
        detail_log("%s: serial %d modulo %d expected %d found %d" % \
                   (msg, serial, MODULO_B, modulo_a, serial % MODULO_B))

def check_serials(serials, modulo_a, msg):
    for z in serials:
        check_serial(serials[z], modulo_a, msg)

t = Test()

master = t.server("knot")
knot = t.server("knot")
zones = t.zone("example.com.")
if "xfr" in SCENARIO:
    source = master
    t.link(zones, master, knot)
else:
    source = knot
    t.link(zones, knot)

for z in zones:
    knot.dnssec(z).enable = True
    knot.zones[z.name].serial_modulo = "%d/%d" % (MODULO_A, MODULO_B)

    knot.zonefile_load = "difference-no-serial"
    knot.zones[z.name].journal_content = "all"

detail_log("SCENARIO " + SCENARIO)
t.start()

serials = knot.zones_wait(zones)
check_serials(serials, MODULO_A, "INIT")
source.ctl("zone-flush", wait=True)

if "ddns" in SCENARIO:
    for z in zones:
        source.random_ddns(z, allow_empty=False)
else:
    for z in zones:
        source.zones[z.name].zfile.update_rnd()

if "start" in SCENARIO:
    source.stop()
    source.start()
elif "reload" in SCENARIO:
    source.ctl("zone-reload")

serials = knot.zones_wait(zones, serials)
check_serials(serials, MODULO_A, "DDNS")

t.end()
