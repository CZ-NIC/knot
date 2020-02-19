#!/usr/bin/env python3

'''Test of Catalog zones.'''

from dnstest.test import Test
from dnstest.utils import set_err, detail_log
import dnstest.params

import glob
import shutil
from subprocess import DEVNULL, PIPE, Popen
import subprocess

def check_keys(server, zone_name, expect_keys):
    cmd = Popen([dnstest.params.keymgr_bin, "-d", server.dir + "/keys", zone_name, "list"], stdout=PIPE, stderr=PIPE, universal_newlines=True)
    (stdout, stderr) = cmd.communicate()
    lines = len(stdout.splitlines())
    if lines != expect_keys:
        set_err("CHECK # of KEYS (%d != %d)" % (lines, expect_keys))

t = Test()

master = t.server("knot")
slave = t.server("knot")

# Zone setup
zone = t.zone("example.com.") + t.zone("catalog1.", storage=".")

t.link(zone, master, slave, ixfr=True)

master.zones["catalog1."].catalog = True
slave.zones["catalog1."].catalog = True

slave.dnssec(zone[1]).enable = True

for zf in glob.glob(t.data_dir + "/*.zone"):
    shutil.copy(zf, master.dir + "/master")

t.start()

# Basic: master a slave configure cataloged zone.
t.sleep(5)
resp = master.dig("cataloged1.", "SOA")
resp.check(rcode="NOERROR")
resp = slave.dig("cataloged1.", "DNSKEY", dnssec=True)
resp.check(rcode="NOERROR")
resp.check_count(2, "DNSKEY")
resp.check_count(1, "RRSIG")

# Udating a cataloged zone
subprocess.run(["sed", "-i", "s/10001/10002/;$s/$/\\nxyz A 1.2.3.4/", master.dir + "/master/cataloged1.zone"])
master.ctl("zone-reload cataloged1.")
t.sleep(4)
resp = slave.dig("xyz.cataloged1.", "A", dnssec=True)
resp.check(rcode="NOERROR")
resp.check_count(1, "RRSIG")

check_keys(slave, "cataloged1", 2)

# Check adding cataloged zone.
up = master.update(zone[1])
up.add("bar.catalog1.", 3600, "PTR", "cataloged2.")
up.send("NOERROR")
t.sleep(2)
resp = master.dig("cataloged2.", "NS")
resp.check(rcode="NOERROR")
resp = slave.dig("cataloged2.", "DNSKEY", dnssec=True)
resp.check(rcode="NOERROR")
resp.check_count(2, "DNSKEY")
resp.check_count(1, "RRSIG")

# Check removing cataloged zone.
up = master.update(zone[1])
up.delete("foo.bar.catalog1.", "PTR")
up.send("NOERROR")
t.sleep(2)
resp = master.dig("cataloged1.", "SOA")
resp.check(rcode="REFUSED")
resp = slave.dig("cataloged1.", "DNSKEY")
resp.check(rcode="REFUSED")

# Check inaccessibility of catalog zone
slave.ctl("conf-begin")
slave.ctl("conf-unset zone[catalog1.].acl") # remove transfer-related ACLs
slave.ctl("conf-commit")
t.sleep(1)
resp = slave.dig("abc.catalog1.", "A")
resp.check(rcode="REFUSED")

t.end()
