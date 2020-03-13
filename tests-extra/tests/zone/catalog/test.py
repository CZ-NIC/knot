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
up.add("bar.catalog1.", 0, "PTR", "cataloged2.")
up.send("NOERROR")
t.sleep(6)
resp = master.dig("cataloged2.", "NS")
resp.check(rcode="NOERROR")
resp = slave.dig("cataloged2.", "DNSKEY", dnssec=True)
resp.check(rcode="NOERROR")
resp.check_count(2, "DNSKEY")
resp.check_count(1, "RRSIG")

# Check that addition didn't delete prvious
resp = master.dig("cataloged1.", "SOA")
resp.check(rcode="NOERROR")
resp = slave.dig("cataloged1.", "SOA", dnssec=True)
resp.check(rcode="NOERROR")
resp.check_count(1, "RRSIG")

# Check remove-adding tha same catalog record: shall not purge it

resp0 = slave.dig("cataloged2.", "DNSKEY")
resp0.check_count(2, "DNSKEY")
dnskey0 = resp0.resp.answer[0].to_rdataset()[0]
up = master.update(zone[1])
up.delete("bar.catalog1.", "PTR", "cataloged2.")
up.add("bar.catalog1.", 0, "PTR", "cataloged2.")
up.send("NOERROR")
t.sleep(4)
resp1 = slave.dig("cataloged2.", "DNSKEY")
resp1.check_count(2, "DNSKEY")
match = 0
if resp1.count("DNSKEY") > 0:
    for dnskey1 in resp1.resp.answer[0].to_rdataset():
        if dnskey1.to_text() == dnskey0.to_text():
             match = match + 1
if match < 1:
    set_err("ZONE PURGED")
    dnskey1 = dnskey0
else:
    dnskey1 = resp1.resp.answer[0].to_rdataset()[0]

# Check remove-adding the zone: shall effectively purge it

up = master.update(zone[1])
up.delete("bar.catalog1.", "PTR", "cataloged2.")
up.add("bar2.catalog1.", 0, "PTR", "cataloged2.")
up.send("NOERROR")
t.sleep(4)
shutil.copy(t.data_dir + "/cataloged2.zone", master.dir + "/master") # because the purge deletes even zonefile
master.ctl("zone-reload cataloged2.")
t.sleep(6)
resp2 = slave.dig("cataloged2.", "DNSKEY")
resp2.check_count(2, "DNSKEY")
if resp2.count("DNSKEY") > 0:
    for dnskey2 in resp2.resp.answer[0].to_rdataset():
        if dnskey1.to_text() == dnskey2.to_text():
            set_err("ZONE NOT PURGED")

# Check persistence after server restart.
slave.stop()
slave.start()
t.sleep(8)
resp = master.dig("cataloged1.", "SOA")
resp.check(rcode="NOERROR")
resp = slave.dig("cataloged1.", "SOA", dnssec=True)
resp.check(rcode="NOERROR")
resp.check_count(1, "RRSIG")
resp = master.dig("cataloged2.", "SOA")
resp.check(rcode="NOERROR")
resp = slave.dig("cataloged2.", "SOA", dnssec=True)
resp.check(rcode="NOERROR")
resp.check_count(1, "RRSIG")

# Check removing cataloged zone.
up = master.update(zone[1])
up.delete("foo.bar.catalog1.", "PTR")
up.send("NOERROR")
t.sleep(6)
resp = master.dig("cataloged1.", "SOA")
resp.check(rcode="REFUSED")
resp = slave.dig("cataloged1.", "DNSKEY")
resp.check(rcode="REFUSED")
check_keys(slave, "cataloged1", 0)

# Check inaccessibility of catalog zone
slave.ctl("conf-begin")
slave.ctl("conf-unset zone[catalog1.].acl") # remove transfer-related ACLs
slave.ctl("conf-commit")
t.sleep(3)
resp = slave.dig("abc.catalog1.", "A")
resp.check(rcode="REFUSED")

t.end()
