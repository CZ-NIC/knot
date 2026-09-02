#!/usr/bin/env python3

'''Test of chained catalog interpreter and generator.'''

from dnstest.utils import *
from dnstest.test import Test
import glob
import random
import shutil
import threading

t = Test(tsig=False, stress=False) # TSIG prevents zone_wait(catz)

master = t.server("knot")

catz = t.zone("catalog1.", storage=".")
bigz = t.zone_rnd(1, records=(32 if master.valgrind else 768), dnssec=False)
smallz = t.zone("example.")
zones = catz + bigz + smallz

t.link(zones, master)
Z = smallz[0].name

master.cat_interpret(catz[0])

master.conf_srv().background_workers = 2
master.conf_srv().async_start = True

master.dnssec(bigz).enable = True
master.dnssec(bigz).nsec3 = True
master.dnssec(bigz).signing_threads = 1
master.dnssec(bigz).algorithm = "RSASHA512"

master.conf_zone(bigz).zonefile_sync = -1

if not master.valgrind:
    master.dnssec(bigz).zsk_size = 4096

def tstart(pt):
    pt.start()
threading.Thread(target=tstart, args=(t,)).start()

cs = master.zone_wait(catz)
s = master.zone_wait(smallz)

bs = master.zone_wait(bigz)
master.zones[bigz[0].name].zfile.update_rnd()
master.zones[catz[0].name].zfile.update_soa()
master.ctl("zone-reload")

master.zone_wait(catz, cs)

confsock = ["-s", os.path.join(master.dir, "knot2.sock"), "-t", "120"] #master.ctl_sock_rnd()

master.ctl("zone-sign %s" % bigz[0].name, wait=True, custom_parm=confsock)

master.zone_wait(bigz, bs+1)

t.end()
