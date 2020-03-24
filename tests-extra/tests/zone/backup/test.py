#!/usr/bin/env python3

'''Test zone backup.'''

from dnstest.test import Test
import shutil

def get_dnskeys(server, zones):
   return [ str(server.dig(z.name, "DNSKEY").resp.answer[0].to_rdataset()) for z in zones ]

t = Test()

zones = t.zone("example.com.") + t.zone("records.")

master = t.server("knot")

t.link(zones, master)

for z in zones:
    master.dnssec(z).enable = True

backup_dir = master.dir + "/backup"

t.start()
master.zones_wait(zones)

master.ctl("zone-backup +backupdir %s" % backup_dir)

(dnskey1_1, dnskey2_1) = get_dnskeys(master, zones)

t.sleep(3)
master.stop()
shutil.rmtree(master.keydir) # let Knot generate new set of keys
master.start()
master.zones_wait(zones)

(dnskey1_2, dnskey2_2) = get_dnskeys(master, zones)
if dnskey1_2 == dnskey1_1 or dnskey2_2 == dnskey2_1:
    set_err("TEST ERROR")

master.ctl("zone-restore +backupdir %s %s" % (backup_dir, zones[0].name))

t.sleep(6)

(dnskey1_3, dnskey2_3) = get_dnskeys(master, zones)
if dnskey1_3 != dnskey1_1:
    set_err("KEYS NOT RESTORED")
if dnskey2_3 == dnskey2_1:
    set_err("KEYS WRONGLY RESTORED")

master.stop()
shutil.rmtree(master.keydir)
shutil.copytree(backup_dir + "/keys", master.keydir) # offline restore
master.start()
master.zones_wait(zones)

(dnskey1_4, dnskey2_4) = get_dnskeys(master, zones)
if dnskey1_4 != dnskey1_1 or dnskey2_4 != dnskey2_1:
    set_err("KEYS NOT RESTORED 2")

t.stop()
