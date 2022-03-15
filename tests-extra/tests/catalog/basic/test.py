#!/usr/bin/env python3

'''Test of Catalog zones.'''

from dnstest.test import Test
from dnstest.utils import set_err, detail_log
from dnstest.module import ModOnlineSign
import dnstest.params

import glob
import shutil
from subprocess import DEVNULL, PIPE, Popen
import subprocess
import random

def check_keys(server, zone_name, expect_keys):
    cmd = Popen([dnstest.params.keymgr_bin, "-D", server.dir + "/keys", zone_name, "list", "-v"], \
                stdout=PIPE, stderr=PIPE, universal_newlines=True)
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

if random.choice([True, False]):
    slave.dnssec(zone[1]).enable = True
else:
    slave.add_module(zone[1], ModOnlineSign(algorithm="ECDSAP256SHA256", single_type_signing=False))

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
resp = master.dig("not-cataloged1.", "SOA")
resp.check(rcode="REFUSED")
resp = master.dig("not-cataloged2.", "SOA")
resp.check(rcode="REFUSED")
resp = master.dig("not-cataloged3.", "SOA")
resp.check(rcode="REFUSED")

# Updating a cataloged zone
subprocess.run(["sed", "-i", "s/10001/10002/;$s/$/\\nxyz A 1.2.3.4/", master.dir + "/master/cataloged1.zone"])
master.ctl("zone-reload cataloged1.")
t.sleep(4)
resp = slave.dig("xyz.cataloged1.", "A", dnssec=True)
resp.check(rcode="NOERROR")
resp.check_count(1, "RRSIG")

check_keys(slave, "cataloged1", 2)

# Check adding cataloged zone.
up = master.update(zone[1])
up.add("bar.zones.catalog1.", 0, "PTR", "cataloged2.")
up.send("NOERROR")
t.sleep(6)
resp = master.dig("cataloged2.", "NS")
resp.check(rcode="NOERROR")
resp = slave.dig("cataloged2.", "DNSKEY", dnssec=True)
resp.check(rcode="NOERROR")
resp.check_count(2, "DNSKEY")
resp.check_count(1, "RRSIG")

# Check that addition didn't delete previous
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
up.delete("bar.zones.catalog1.", "PTR", "cataloged2.")
up.add("bar.zones.catalog1.", 0, "PTR", "cataloged2.")
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
up.delete("bar.zones.catalog1.", "PTR", "cataloged2.")
up.add("bar2.zones.catalog1.", 0, "PTR", "cataloged2.")
up.send("NOERROR")
t.sleep(4)
shutil.copy(t.data_dir + "/cataloged2.zone", master.dir + "/master") # because the purge deletes even zonefile
master.ctl("zone-reload cataloged2.")
t.sleep(2)
master.ctl("zone-notify cataloged2.")
t.sleep(4)
resp2 = slave.dig("cataloged2.", "DNSKEY")
resp2.check_count(2, "DNSKEY")
if resp2.count("DNSKEY") > 0:
    for dnskey2 in resp2.resp.answer[0].to_rdataset():
        if dnskey1.to_text() == dnskey2.to_text():
            set_err("ZONE NOT PURGED")
dnskey2 = resp2.resp.answer[0].to_rdataset()[0]

# Check persistence after server restart
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

# Check adding and removing duplicate
up = master.update(zone[1])
up.add("bar3.zones.catalog1.", 0, "PTR", "cataloged2.")
up.send("NOERROR")
t.sleep(6)
up = master.update(zone[1])
up.delete("bar3.zones.catalog1.", "PTR")
up.send("NOERROR")
t.sleep(6)
resp = master.dig("cataloged2.", "SOA")
resp.check(rcode="NOERROR")
resp = slave.dig("cataloged2.", "SOA", dnssec=True)
resp.check(rcode="NOERROR")
check_keys(slave, "cataloged2", 2)

# Check adding two-RR member PTR
up = master.update(zone[1])
up.add("bar2.zones.catalog1.", 0, "PTR", "catalogedx.")
up.add("bar4.zones.catalog1.", 0, "PTR", "catalogedy.")
up.send("SERVFAIL")
t.sleep(6)
resp = master.dig("catalogedy.", "SOA")
resp.check(rcode="REFUSED")

master.ctl("zone-backup +journal +backupdir %s/backup %s" % (master.dir, zone[1].name))
# Check removing cataloged zone
up = master.update(zone[1])
up.delete("foo.zones.catalog1.", "PTR")
up.send("NOERROR")
t.sleep(6)
resp = master.dig("cataloged1.", "SOA")
resp.check(rcode="REFUSED")
resp = slave.dig("cataloged1.", "DNSKEY")
resp.check(rcode="REFUSED")
check_keys(slave, "cataloged1", 0)

# Check restoring catalog from backup
master.ctl("zone-restore +journal +backupdir %s/backup %s" % (master.dir, zone[1].name))
t.sleep(6)
resp = master.dig("cataloged2.", "SOA")
resp.check(rcode="NOERROR")

# Check inaccessibility of catalog zone
slave.ctl("conf-begin")
slave.ctl("conf-unset zone[catalog1.].acl") # remove transfer-related ACLs
slave.ctl("conf-commit")
t.sleep(3)
resp = slave.dig("abc.catalog1.", "A")
resp.check(rcode="REFUSED")

t.end()
