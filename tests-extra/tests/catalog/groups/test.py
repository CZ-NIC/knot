#!/usr/bin/env python3

'''Test of consuming catalog with configuration groups.'''

from dnstest.test import Test
from dnstest.utils import set_err, detail_log
from dnstest.module import ModOnlineSign
import dnstest.params

import glob
import os
import shutil
from subprocess import DEVNULL, PIPE, Popen
import subprocess
import random

def check_keys(server, zone_name, expect_keys):
    cmd = Popen([dnstest.params.keymgr_bin, "-D", server.dir + "/keys", zone_name, "list", "-e"], \
                stdout=PIPE, stderr=PIPE, universal_newlines=True)
    (stdout, stderr) = cmd.communicate()
    lines = len(stdout.splitlines())
    if lines != expect_keys:
        set_err("CHECK # of KEYS (%d != %d)" % (lines, expect_keys))

t = Test(stress=False)

master = t.server("knot")

# Zone setup
zone = t.zone("catalog2.", storage=".")

t.link(zone, master)

master.cat_interpret(zone)

os.mkdir(master.dir + "/catalog")
for zf in glob.glob(t.data_dir + "/*.zone"):
    shutil.copy(zf, master.dir + "/catalog")

t.start()

# Basic: catalogedX are assigned to correct groups
t.sleep(5)
resp = master.dig("cataloged1.", "SOA", dnssec=True)
resp.check(rcode="NOERROR")
resp.check_count(1, "RRSIG")
resp = master.dig("cataloged2.", "SOA", dnssec=True)
resp.check(rcode="NOERROR")
resp.check_count(0, "RRSIG")
resp = master.dig("cataloged3.", "SOA", dnssec=True)
resp.check(rcode="NOERROR")
resp.check_count(0, "RRSIG")

# Addition of member with group
up = master.update(zone)
up.add("added.zones.catalog2.", 0, "PTR", "cataloged4.")
up.add("group.added.zones.catalog2.", 0, "TXT", "catalog-signed")
up.send("NOERROR")
t.sleep(4)
resp = master.dig("cataloged4.", "SOA", dnssec=True)
resp.check(rcode="NOERROR")
resp.check_count(1, "RRSIG")

# Move member between groups
up = master.update(zone)
up.delete("group.bar.zones.catalog2.", "TXT")
up.add("group.bar.zones.catalog2.", 0, "TXT", "catalog-signed")
up.send("NOERROR")
t.sleep(4)
resp = master.dig("cataloged2.", "SOA", dnssec=True)
resp.check(rcode="NOERROR")
resp.check_count(1, "RRSIG")

# Add member to a group
up = master.update(zone)
up.add("group.baz.zones.catalog2.", 0, "TXT", "catalog-signed")
up.send("NOERROR")
t.sleep(4)
resp = master.dig("cataloged3.", "SOA", dnssec=True)
resp.check(rcode="NOERROR")
resp.check_count(1, "RRSIG")

# Remove member from any group
up = master.update(zone)
up.delete("group.foo.zones.catalog2.", "TXT")
up.send("NOERROR")
t.sleep(4)
# check that DNSSEC no longer works
with open(master.dir + "/catalog/cataloged1.zone", "a") as c1zf:
    c1zf.write("added A 1.2.3.4")
master.ctl("zone-reload cataloged1.")
t.sleep(4)
resp = master.dig("added.cataloged1.", "A", dnssec=True)
resp.check(rcode="NOERROR")
resp.check_count(1, "A")
resp.check_count(0, "RRSIG")

# Remove member while adding group
up = master.update(zone)
up.delete("foo.zones.catalog2.", "PTR")
up.add("group.foo.zones.catalog2.", 0, "TXT", "catalog-signed")
up.send("NOERROR")
t.sleep(4)
resp = master.dig("cataloged1.", "SOA", dnssec=True)
resp.check(rcode="REFUSED")
check_keys(master, "cataloged1.", 0)

t.end()
