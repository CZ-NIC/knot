#!/usr/bin/env python3

"""
Test of difference-no-serial with possibly zero SOA serial.
"""

from dnstest.utils import *
from dnstest.test import Test
import dnstest.params
from subprocess import PIPE, Popen
import random

def journal_changesets(server, zone):
    zij = 0
    chs = 0

    pipe = Popen([dnstest.params.kjournalprint_bin, "-d", "-c", server.confile, zone.name], stdout=PIPE, stderr=PIPE, universal_newlines=True)
    (stdout, stderr) = pipe.communicate()
    for line in stdout.splitlines():
        tokens = line.split()
        if tokens[0].lower() == "zone-in-journal":
            zij += 1
        if len(tokens) > 1 and tokens[1] == "->":
            chs += 1
    return (zij, chs)

def check_journal(server, zone, expect_zij, expect_chs):
    (zij, chs) = journal_changesets(server, zone)
    if zij != expect_zij:
        set_err("ZONE-IN-JOURNAL")
        detail_log("Zone-in-journal not stored as expected: (%d != %d)" % (zij, expect_zij))
    if chs != expect_chs:
        set_err("CHANGESETS")
        detail_log("Changesets not stored as expected: (%d != %d)" % (chs, expect_chs))

t = Test()

start_version = random.choice([0, 2])

knot = t.server("knot")
zone = t.zone("example.com.", storage=".")
t.link(zone, knot)
knot.zonefile_sync = "-1"
knot.zones[zone[0].name].journal_content = "all"
knot.zonefile_load = "difference-no-serial"

knot.update_zonefile(zone, version=start_version)

t.start()
serial = knot.zone_wait(zone)
check_journal(knot, zone[0], 1, 0)

knot.update_zonefile(zone, version=start_version+1)
knot.ctl("zone-reload")
serial = knot.zone_wait(zone, serial)
t.sleep(1)
check_journal(knot, zone[0], 1, 1)

if start_version == 0:
    knot.update_zonefile(zone, version=2)
    knot.stop()
    t.sleep(1)
    knot.start()
    serial = knot.zone_wait(zone, serial)
    check_journal(knot, zone[0], 1, 2)
    
    knot.update_zonefile(zone, version=3)
    knot.ctl("zone-reload")
    serial = knot.zone_wait(zone, serial)
    t.sleep(1)
    check_journal(knot, zone[0], 1, 3)

t.end()
