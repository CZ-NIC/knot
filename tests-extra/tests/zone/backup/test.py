#!/usr/bin/env python3

'''Test zone backup.'''

from dnstest.test import Test
import shutil

t = Test()

zones = t.zone("example.com.")

master = t.server("knot")

t.link(zones, master)

for z in zones:
    master.dnssec(z).enable = True

backup_dir = master.dir + "/backup"

t.start()
master.zones_wait(zones)

master.ctl("zone-backup +backupdir %s" % backup_dir)

resp = master.dig(zones[0].name, "DNSKEY")
dnskey1 = str(resp.resp.answer[0].to_rdataset())

t.sleep(3)
master.stop()
shutil.rmtree(master.keydir) # let Knot generate new set of keys
master.start()
master.zones_wait(zones)

resp = master.dig(zones[0].name, "DNSKEY")
dnskey2 = str(resp.resp.answer[0].to_rdataset())
if dnskey2 == dnskey1:
    set_err("TEST ERROR")

master.ctl("zone-restore +backupdir %s" % backup_dir)

t.sleep(6)

resp = master.dig(zones[0].name, "DNSKEY")
dnskey3 = str(resp.resp.answer[0].to_rdataset())

if dnskey3 != dnskey1:
    set_err("KEYS NOT RESTORED")

t.stop()
