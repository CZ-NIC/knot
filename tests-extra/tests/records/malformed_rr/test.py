#!/usr/bin/env python3

'''Test of load/dump behavior with malformed record(s) (e.g. 2-byte A).'''

from dnstest.test import Test
from dnstest.utils import *
import shutil

t = Test()

master = t.server("knot")
slave = t.server("knot")
zfloader = t.server("knot")
ZONE = "example.com."
zone = t.zone(ZONE)

t.link(zone, master, slave)
t.link(zone, zfloader)

master.conf_zone(zone).zonefile_load = "none"
master.conf_zone(zone).journal_content = "all"

zfloader.conf_zone(zone).zonefile_load = "difference-no-serial"
zfloader.conf_zone(zone).journal_content = "all"

shutil.copytree(os.path.join(t.data_dir, "journal"), os.path.join(master.dir, "journal"))

t.start()

serial = master.zone_wait(zone)
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

try:
    resp = master.dig("svcb." + ZONE, "SVCB", timeout=0.3)
    resp.check(rcode="NOERROR")
except Failed:
    pass

resp = slave.dig("dns2." + ZONE, "A")
resp.check(rcode="SERVFAIL", nordata="192.0.2.2")

resp = slave.dig("svcb." + ZONE, "SVCB")
resp.check(rcode="SERVFAIL")

resp = zfloader.dig("svcb." + ZONE, "SVCB")
resp.check(rcode="NXDOMAIN")

shutil.copyfile(master.zones[ZONE].zfile.path, zfloader.zones[ZONE].zfile.path)
zfloader.ctl("zone-reload", wait=True)

zfloader.zone_wait(zone, serial)

resp = zfloader.dig("dns2." + ZONE, "A")
resp.check(rcode="NOERROR", rdata="192.0.2.2")

resp = zfloader.dig("dns1." + ZONE, "A")
resp.check(rcode="SERVFAIL", nordata="192.0.2.1")

try:
    resp = zfloader.dig("svcb." + ZONE, "SVCB", timeout=0.3)
    resp.check(rcode="NOERROR")
except Failed:
    pass

t.end()
