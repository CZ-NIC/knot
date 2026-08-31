#!/usr/bin/env python3

'''Test of mutual blocking of catalog processing and big zone signing.'''

from dnstest.utils import *
from dnstest.test import Test
import glob
import random
import shutil
import threading

t = Test(tsig=False) # TSIG prevents zone_wait(catz)

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

confsock = master.ctl_sock_rnd()

master.ctl("zone-status", custom_parm=confsock)

master.ctl("zone-begin %s" % Z, custom_parm=confsock)
master.ctl("zone-set %s dewjhdlkwjd 3600 A 1.1.1.1" % Z, custom_parm=confsock)
master.ctl("zone-commit %s" % Z, custom_parm=confsock)

resp = master.dig("dewjhdlkwjd.%s" % Z, "A")
resp.check(rcode="NOERROR", rdata="1.1.1.1")

master.zones[Z].zfile.update_soa(serial=(s+2))
master.ctl("zone-reload %s" % Z, custom_parm=confsock)

resp = master.dig(bigz[0].name, "SOA")
resp.check(rcode="SERVFAIL") # otherwise test failure, signing too fast

resp = master.dig("records.com.", "SOA")
resp.check(rcode="REFUSED") # otherwise test failure, signing too fast

master.ctl("reload", custom_parm=confsock) # blocks until catalog is populated and earlier zone-reload processed

bs = master.zone_wait(bigz)
t.sleep(1)
resp = master.dig("records.com.", "SOA")
resp.check(rcode="SERVFAIL")

resp = master.dig("dewjhdlkwjd.%s" % Z, "A")
resp.check(rcode="NXDOMAIN", nordata="1.1.1.1")

master.zones[bigz[0].name].zfile.update_rnd()
master.zones[catz[0].name].zfile.update_soa()
master.ctl("zone-reload")

master.zone_wait(catz, cs)

master.ctl("zone-status", custom_parm=confsock)

master.ctl("zone-begin %s" % Z, custom_parm=confsock)
master.ctl("zone-set %s djeljdlkejeee 3600 A 1.1.1.1" % Z, custom_parm=confsock)
master.ctl("zone-commit %s" % Z, custom_parm=confsock)

resp = master.dig("djeljdlkejeee.%s" % Z, "A")
resp.check(rcode="NOERROR", rdata="1.1.1.1")

master.zones[Z].zfile.update_soa(serial=(s+4))
master.ctl("zone-reload %s" % Z, custom_parm=confsock)

t.sleep(25)
master.ctl("reload", custom_parm=confsock) # blocks until catalog is populated and earlier zone-reload processed

master.zone_wait(bigz, bs)
t.sleep(1)

resp = master.dig("djeljdlkejeee.%s" % Z, "A")
resp.check(rcode="NXDOMAIN", nordata="1.1.1.1")

t.end()
