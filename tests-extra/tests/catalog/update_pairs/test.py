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

def sign_wait(tolaunch, zonename):
    check_call(tolaunch, stdout=DEVNULL, stderr=DEVNULL)

def sign_wait_bg(server, zonename):
    server[-1] = "120" # timeout
    tolaunch = server + ["-b", "zone-sign", zonename]
    threading.Thread(target=sign_wait, args=[tolaunch, zonename]).start()

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
knot.bg_workers = 4

knot.semantic_check = False

catz = t.zone("catalog1.", storage=".")
rzone = t.zone(".") # to slow down background workers
rzone[0].update_rnd() # it needs to be larger, slower

t.link(catz, knot, journal_content = "none")
t.link(rzone, knot, journal_content = "none")
knot.cat_interpret(catz)

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
        knot.dnssec(z).nsec3_iters = "65000"
        knot.dnssec(z).alg = "rsasha512"
        knot.dnssec(z).zsk_size = "4096"

# Whether to test a property change instead of add/del.
scenario = random.choice(["addrem", "propchange", "uniq2x"])
detail_log("SCENARIO " + scenario)

t.start()

rootser = knot.zone_wait(rzone)
t.sleep(5)

for z in rzone:
    knot.ctl("zone-sign " + z.name)
t.sleep(0.5)

for z in rzone:
    sign_wait_bg([knot.control_bin] + knot.ctl_params, z.name)
t.sleep(1)

up = knot.update(catz)
if scenario == "uniq2x":
    up.delete("uniq1.zones." + catz[0].name, "PTR", "cataloged1.")
    up.add("uniq2.zones." + catz[0].name, 0, "PTR", "cataloged1.")
else:
    up.add("bar.zones." + catz[0].name, 0, "PTR", "cataloged2.")
up.try_send()

t.sleep(0.5)

up = knot.update(catz)
if scenario == "uniq2x":
    up.delete("uniq2.zones." + catz[0].name, "PTR", "cataloged1.")
    up.add("uniq3.zones." + catz[0].name, 0, "PTR", "cataloged1.")
elif scenario == "propchange":
    up.delete("group.bar.zones." + catz[0].name, "TXT")
    up.add("group.bar.zones." + catz[0].name, 0, "TXT", "catalog-signed")
else:
    up.delete("bar.zones." + catz[0].name, "PTR", "cataloged2.")
up.try_send()

knot.zone_wait(rzone, rootser + 2, equal=True) # signed twice
t.sleep(10)

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
    resp.check(rcode="NXDOMAIN") # not REFUSED due to presence of root zone;
                                 # not SERVFAIL what is the point of the test

    # Check the catalog DB.
    knot.stop()
    check_catalog_db(knot, "cataloged2.")

t.end()
