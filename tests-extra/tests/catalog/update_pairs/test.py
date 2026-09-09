#!/usr/bin/env python3

'''Test of a combined addition to and removal from a catalog.'''

from dnstest.test import Test
from dnstest.utils import set_err, detail_log, check_log
import dnstest.params

import glob
import os
import random
import time
import hashlib
import threading
import shutil
from subprocess import Popen, PIPE, DEVNULL, check_call

def check_catalog_db(server, memb_name):
    '''Check that the member is not present in server's catalog DB'''
    pipe = Popen([dnstest.params.kcatalogprint_bin, "-c", server.confile],
                 stdout=PIPE, stderr=PIPE, universal_newlines=True)
    (stdout, stderr) = pipe.communicate()
    for line in stdout.splitlines():
        if line.startswith(memb_name + " "):
            set_err("MEMBER LEFT IN CATALOG DB")
            check_log("ERROR: MEMBER %s LEFT IN CATALOG DB" % memb_name)
            return False
    return True

#t = Test(stress=False) # switch the stressing off for better log readability
t = Test()

knot = t.server("knot")

catz = t.zone("catalog1.", storage=".")
rzone = t.zone_rnd(1, records=800, names=["bigzone.example."]) # to slow down background workers

t.link(catz, knot)
t.link(rzone, knot)
knot.cat_interpret(catz)

knot.ctl_timeout = 110
knot.conf_srv().background_workers = 4
knot.conf_zone(catz + rzone).journal_content = "none"
knot.conf_zone(catz + rzone).semantic_checks = False

catalog_dir = os.path.join(knot.dir, "catalog")
os.mkdir(catalog_dir)
for zf in glob.glob(t.data_dir + "/*.zone"):
    shutil.copy(zf, knot.dir + "/catalog")

for z in rzone:
    # slow down processing as much as possible
    knot.dnssec(z).enable = True
    knot.dnssec(z).signing_threads = "2"
    if not knot.valgrind: # it would be too slow with valgrind
        knot.dnssec(z).nsec3 = True
        knot.dnssec(z).nsec3_iterations = "1"
        knot.dnssec(z).algorithm = "rsasha512"
        knot.dnssec(z).zsk_size = "4096"

# Whether to test a property change instead of add/del.
scenario = random.choice(["addrem", "propchange", "uniq2x"])
detail_log("SCENARIO " + scenario)

t.start()

rootser = knot.zone_wait(rzone)
t.sleep(5)

for z in rzone:
    knot.ctl("zone-sign " + z.name)
t.sleep(1)

confsock = knot.ctl_sock_rnd()
knot.ctl("zone-begin %s" % catz[0].name, custom_parm=confsock)
if scenario == "uniq2x":
    knot.ctl("zone-unset %s uniq1.zones" % catz[0].name, custom_parm=confsock)
    knot.ctl("zone-set %s uniq2.zones 0 PTR cataloged1." % catz[0].name, custom_parm=confsock)
else:
    knot.ctl("zone-set %s bar.zones 0 PTR cataloged2." % catz[0].name, custom_parm=confsock)
    knot.ctl("zone-set %s group.bar.zones 0 TXT catalog-unsigned" % catz[0].name, custom_parm=confsock)
knot.ctl("zone-commit %s" % catz[0].name, custom_parm=confsock)

t.sleep(0.5)

knot.ctl("zone-begin %s" % catz[0].name, custom_parm=confsock)
if scenario == "uniq2x":
    knot.ctl("zone-unset %s uniq2.zones" % catz[0].name, custom_parm=confsock)
    knot.ctl("zone-set %s uniq3.zones 0 PTR cataloged1." % catz[0].name, custom_parm=confsock)
elif scenario == "propchange":
    knot.ctl("zone-unset %s group.bar.zones" % catz[0].name, custom_parm=confsock)
    knot.ctl("zone-set %s group.bar.zones 0 TXT catalog-signed" % catz[0].name, custom_parm=confsock)
else:
    knot.ctl("zone-unset %s bar.zones" % catz[0].name, custom_parm=confsock)
    knot.ctl("zone-unset %s group.bar.zones" % catz[0].name, custom_parm=confsock)
knot.ctl("zone-commit %s" % catz[0].name, custom_parm=confsock)

knot.zone_wait(rzone, rootser + 1, equal=True)
t.sleep(2)

if scenario == "uniq2x":
    # Check the catalog zone.
    resp = knot.dig("uniq3.zones.catalog1.", "PTR", tsig=True)
    resp.check(rcode="NOERROR", rdata="cataloged1.")

    # Check a DNS query / zonedb.
    resp = knot.dig("cataloged1.", "SOA")
    resp.check(rcode="SERVFAIL") # the zone got purged

elif scenario == "propchange":
    # Check successfull change of a zone group.
    t.sleep(4)
    resp = knot.dig("cataloged2.", "SOA", dnssec=True)
    resp.check(rcode="NOERROR")
    resp.check_count(1, "RRSIG")

else:
    # Check the catalog zone.
    resp = knot.dig("bar.zones.catalog1.", "PTR", tsig=True)
    resp.check(rcode="NXDOMAIN", nordata="PTR")

    # Check a DNS query / zonedb.
    resp = knot.dig("cataloged2.", "SOA")
    resp.check(rcode="REFUSED") # not SERVFAIL what is the point of the test

    # Check the catalog DB.
    knot.stop()
    check_catalog_db(knot, "cataloged2.")

t.end()
