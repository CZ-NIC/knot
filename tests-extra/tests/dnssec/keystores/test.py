#!/usr/bin/env python3

"""
Check of multi-keystore operation.
"""

import os
import random
import shutil
from dnstest.utils import *
from dnstest.keys import Keymgr
from dnstest.test import Test

def check_key_count(server, keystore, expected):
    ksdir = os.path.join(server.keydir, keystore)
    try:
        files = len([name for name in os.listdir(ksdir)])
    except FileNotFoundError:
        files = 0
    compare(files, expected, "privkey count in %s" % ksdir)

t = Test()

server = t.server("knot")
zone = t.zone("catalog.") # has zero TTL => faster key rollovers
t.link(zone, server)

server.dnssec(zone).enable = True
server.dnssec(zone).propagation_delay = 1
server.dnssec(zone).keystores = [ "keys1", "keys2" ]

t.start()
serial = server.zone_wait(zone)

check_key_count(server, "keys1", 2)
check_key_count(server, "keys2", 0)

server.dnssec(zone).keystores = [ "keys2", "keys1" ]
server.gen_confile()
server.reload()
server.ctl("zone-key-rollover %s zsk" % zone[0].name)

serial += 2 # wait for three increments which is whole ZSK rollover
serial = server.zone_wait(zone, serial)

check_key_count(server, "keys1", 1)
check_key_count(server, "keys2", 1)

backup_dir = os.path.join(server.dir, "backup1")
server.ctl("zone-backup +backupdir %s %s" % (backup_dir, zone[0].name), wait=True)
shutil.rmtree(os.path.join(server.keydir, "keys1"))
shutil.rmtree(os.path.join(server.keydir, "keys2"))
server.ctl("zone-restore +backupdir %s %s" % (backup_dir, zone[0].name), wait=True)

check_key_count(server, "keys1", 0)
check_key_count(server, "keys2", 2) # restore puts all keys to first configured keystore no matter where they were at backup

server.ctl("zone-sign %s" % zone[0].name, wait=True) # check that signing still works after restore
serial = server.zone_wait(zone, serial)

server.flush(zone[0], wait=True)
server.zone_verify(zone[0])

server.dnssec(zone).keystores = [ "keys0ksk", "keys1", "keys2" ]
server.gen_confile()
server.reload()

server.ctl("zone-key-rollover %s ksk" % zone[0].name)
serial += 1 # wait for two increments
serial = server.zone_wait(zone, serial)
check_key_count(server, "keys0ksk", 1)
check_key_count(server, "keys1", 0)
check_key_count(server, "keys2", 2)

server.ctl("zone-ksk-submitted %s" % zone[0].name)
serial = server.zone_wait(zone, serial)
check_key_count(server, "keys0ksk", 1)
check_key_count(server, "keys1", 0)
check_key_count(server, "keys2", 1)

server.ctl("zone-key-rollover %s zsk" % zone[0].name)
serial += 2 # wait for three increments which is whole ZSK rollover
serial = server.zone_wait(zone, serial)
check_key_count(server, "keys0ksk", 1)
check_key_count(server, "keys1", 1)
check_key_count(server, "keys2", 0)

Keymgr.run_check(server.confile, zone[0].name, "generate", "ksk=yes")
check_key_count(server, "keys0ksk", 2)
check_key_count(server, "keys1", 1)

Keymgr.run_check(server.confile, zone[0].name, "generate", "ksk=no")
check_key_count(server, "keys0ksk", 2)
check_key_count(server, "keys1", 2)

Keymgr.run_check(server.confile, zone[0].name, "import-bind", os.path.join(t.data_dir, "Kcatalog.+013+07147.key"))
check_key_count(server, "keys0ksk", 2)
check_key_count(server, "keys1", 3)

Keymgr.run_check(server.confile, zone[0].name, "import-bind", os.path.join(t.data_dir, "Kcatalog.+013+18635.key"))
check_key_count(server, "keys0ksk", 3)
check_key_count(server, "keys1", 3)

Keymgr.run_check(server.confile, zone[0].name, "import-pem", os.path.join(t.data_dir, "8329a00d5dceefdcbbf7b8a3cdf61fe944c51d6f.pem"), "ksk=yes")
check_key_count(server, "keys0ksk", 4)
check_key_count(server, "keys1", 3)

Keymgr.run_check(server.confile, zone[0].name, "import-pem", os.path.join(t.data_dir, "894d4240398f459f59f4a99cd4c5b658c9a62d54.pem"), "ksk=no")
check_key_count(server, "keys0ksk", 4)
check_key_count(server, "keys1", 4)
check_key_count(server, "keys2", 0)

t.end()
