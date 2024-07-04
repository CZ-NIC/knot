#!/usr/bin/env python3

'''Test deadlocking CTL with zone-begin and blocking zone-sign.'''

from dnstest.utils import *
from dnstest.test import Test
import random
import threading
import time

def background_sign(server, zone_name):
    try:
        server.ctl("-b zone-sign " + zone_name)
    except:
        pass

def background_backup(server, zone_name):
    bckdir = "%s/backup" % server.dir
    server.ctl("zone-backup +backupdir " + bckdir)
    attempts = 10
    while attempts > 0:
        attempts -= 1
        try:
            time.sleep(2)
            server.ctl("zone-restore +backupdir " + bckdir)
            attempts = 0
        except:
            pass

def run_thr(fun, server, zone_name):
    threading.Thread(target=fun, args=[server, zone_name]).start()

t = Test()

master = t.server("knot")
zones = t.zone_rnd(1, dnssec=False, records=40)
t.link(zones, master)

for z in zones:
    master.dnssec(z).enable = True

t.start()
serials = master.zones_wait(zones)
ZONE = zones[0].name

master.ctl("zone-begin " + ZONE)
run_thr(background_sign, master, ZONE)
t.sleep(1)
master.ctl("zone-abort " + ZONE)

t.sleep(1)
serials = master.zones_wait(zones) # check if server is still sane
master.ctl("zone-status " + ZONE)

# scenario 2: zone restore with open txn

BACKUP_FIRST = random.choice([False, True])
detail_log("BACKUP_FIRST: " + str(BACKUP_FIRST))

if not BACKUP_FIRST:
    master.ctl("zone-begin " + ZONE)
run_thr(background_backup, master, ZONE)
if BACKUP_FIRST:
    t.sleep(2.05)
    try:
        master.ctl("zone-begin " + ZONE)
        has_soa = master.ctl("zone-get " + ZONE + " " + ZONE + " SOA", availability=False, read_result=True)
        if not " SOA " in has_soa:
            master.ctl("zone-abort " + ZONE, availability=False)
            raise Exception("restored and not yet loaded")
    except:
        t.sleep(1)
        master.zones_wait(zones)
        master.ctl("zone-begin " + ZONE)
master.ctl("zone-set " + ZONE + " dhowedhhjewodw 3600 A 1.2.3.4")
t.sleep(3)
master.ctl("zone-commit " + ZONE)

master.zones_wait(zones, serials, equal=True, greater=BACKUP_FIRST)
master.ctl("zone-status " + ZONE)

t.end()
