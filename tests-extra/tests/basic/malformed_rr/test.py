#!/usr/bin/env python3

'''Test of load/dump behavior with malformed record(s) (2-byte A).'''

from dnstest.test import Test
from dnstest.utils import *
import shutil

t = Test()

ZONE = "example.com."
master = t.server("knot")
zone = t.zone(ZONE)

t.link(zone, master)

master.zonefile_load = "none"
master.zones[ZONE].journal_content = "all"

shutil.copytree(os.path.join(t.data_dir, "journal"), os.path.join(master.dir, "journal"))

t.start()

master.zone_wait(zone)
master.ctl("zone-flush", wait=True)

generic_a = False
with open(master.zones[ZONE].zfile.path, "r") as f:
    for l in f:
        if "\\# 2 C000" in l:
            generic_a = True

if not generic_a:
    set_err("NO GENERIC A")

resp = master.dig("dns2." + ZONE, "A")
resp.check(rcode="NOERROR", rdata="192.0.2.2")

resp = master.dig("dns1." + ZONE, "A")
resp.check(rcode="SERVFAIL", nordata="192.0.2.1")

t.end()
