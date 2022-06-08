#!/usr/bin/env python3

'''Test zone backup.'''

from dnstest.test import Test
from dnstest.module import ModOnlineSign
from dnstest.utils import *
from dnstest.keys import Keymgr
import shutil
import random

def get_dnskeys(server, zones):
   return [ str(server.dig(z.name, "DNSKEY").resp.answer[0].to_rdataset()) for z in zones ]

def test_added(server, zones, results):
    for (z, res) in zip(zones, results):
        resp = server.dig("added.%s" % z.name, "A")
        resp.check(rcode=res)

t = Test()

zones = t.zone("example.", storage=".") + t.zone("serial.", storage=".")

master = t.server("knot")
slave = t.server("knot")

t.link(zones, master, slave)

for z in zones:
    if random.choice([True, False]):
        master.dnssec(z).enable = True
        master.dnssec(z).algorithm = "ECDSAP256SHA256"
        master.dnssec(z).single_type_signing = False
    else:
        master.add_module(z, ModOnlineSign(algorithm="ECDSAP256SHA256"))
    slave.zones[z.name].journal_content = "all"
    slave.zonefile_load = "none"

backup_dir = master.dir + "/backup"
slave_bck_dir = slave.dir + "/backup"

zone0_expire = 45   # zone zones[0] expiration time in its SOA
valgrind_delay = 2 if slave.valgrind else 0  # allow a little time margin under Valgrind
valgrind_delay += 2 # even without valgrind, add some tolerance because rounding timestamps to whole seconds multiple times

if master.valgrind:
    master.semantic_check = False
    slave.semantic_check = False

t.start()
serials_init = slave.zones_wait(zones)
start_time = int(t.uptime())

for z in zones:
    if master.dnssec(z).enable:
        Keymgr.run_check(master.confile, z.name, "import-pub", "%s/%skey" % (t.data_dir, z.name))
        master.ctl("zone-sign " + z.name)
        slave.zone_wait(z, serials_init[z.name])

master.ctl("zone-backup +backupdir %s" % backup_dir)
slave.ctl("zone-backup %s %s +journal +backupdir %s +nozonefile" % \
          (zones[0].name, zones[1].name, slave_bck_dir))

(dnskey1_1, dnskey2_1) = get_dnskeys(master, zones)

t.sleep(4)

for z in zones:
    up = master.update(z)
    up.delete("added.%s" % z.name, "A")
    up.send()

t.sleep(1)

slave.stop()
master.stop()
shutil.rmtree(master.keydir) # let Knot generate new set of keys
master.start()
master.zones_wait(zones)

(dnskey1_2, dnskey2_2) = get_dnskeys(master, zones)
if dnskey1_2 == dnskey1_1 or dnskey2_2 == dnskey2_1:
    set_err("TEST ERROR")

test_added(master, zones, [ "NXDOMAIN", "NXDOMAIN" ])

shutil.rmtree(master.dir + "/master")
master.ctl("zone-restore +backupdir %s %s" % (backup_dir, zones[0].name), wait=True)

t.sleep(5)

(dnskey1_3, dnskey2_3) = get_dnskeys(master, zones)
if dnskey1_3 != dnskey1_1:
    set_err("KEYS NOT RESTORED")
if dnskey2_3 == dnskey2_1:
    set_err("KEYS WRONGLY RESTORED")

test_added(master, zones, [ "NOERROR", "NXDOMAIN" ])

master.ctl("zone-restore +backupdir %s %s" % (backup_dir, zones[1].name), wait=True)
master.stop()
keydir = master.keydir # BEWARE this is function invocation
shutil.rmtree(keydir)
shutil.copytree(backup_dir + "/keys", keydir) # offline restore

shutil.rmtree(master.dir + "/journal")
master.start()
master.zones_wait(zones)

(dnskey1_4, dnskey2_4) = get_dnskeys(master, zones)
if dnskey1_4 != dnskey1_1 or dnskey2_4 != dnskey2_1:
    set_err("KEYS NOT RESTORED 2")

test_added(master, zones, [ "NOERROR", "NOERROR" ])

master.stop()
shutil.rmtree(slave.dir + "/journal")
shutil.rmtree(slave.dir + "/timers")
slave.start()

slave.ctl("zone-restore +nozonefile +backupdir %s +journal" % slave_bck_dir, wait=True)
if int(t.uptime()) - start_time < zone0_expire - valgrind_delay:
    slave.zones_wait(zones) # zones shall be loaded from recovered journal iff not expired yet

for i in range(start_time + zone0_expire + valgrind_delay - int(t.uptime())):
    t.sleep(1)
    resp = slave.dig(zones[0].name, "SOA")
    if resp.rcode() != "NOERROR":
        break
# the zone should expire in zone0_expire seconds (SOA) according to restored timers

resp = slave.dig(zones[0].name, "SOA")
resp.check(rcode="SERVFAIL")

t.stop()
