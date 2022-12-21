#!/usr/bin/env python3

'''Test for DNSSEC validation of Bind9 master by Knot slave'''

from dnstest.test import Test
from dnstest.utils import *

from subprocess import PIPE, Popen

t = Test()

master = t.server("bind")
slave = t.server("knot")
zones_nsec = t.zone_rnd(3, records=40, dnssec=False)
zones_nsec3 = t.zone_rnd(3, records=40, dnssec=False)
zones = zones_nsec + zones_nsec3

t.link(zones, master, slave, ixfr=True, ddns=True)

for z in zones:
    master.dnssec(z).enable = True
    slave.dnssec(z).validate = True

for z in zones_nsec3:
    master.dnssec(z).nsec3 = True
    master.dnssec(z).nsec3_opt_out = True
    slave.dnssec(z).nsec3 = True

t.start()

serials_init = master.zones_wait(zones)
slave.zones_wait(zones)

serials_prev = serials_init
for i in range(4):
    for z in zones:
        master.random_ddns(z, allow_empty=False)

    serials = master.zones_wait(zones, serials_prev)
    master.flush() # needed for the next master.random_ddns()

    t.sleep(2)
    for z in zones:
        if slave.log_search("[%s] DNSSEC, validation failed (no valid signature for a record)" % z.name.lower()):
            detail_log("!Ignoring zone '%s' with invalid signature" % z.name.lower())
            zones.remove(z)

    slave.zones_wait(zones, serials_prev)
    serials_prev = serials

    t.xfr_diff(master, slave, zones, serials_init)

    slave.flush(wait=True)
    for z in zones:
        ##### Temporary workaround for BIND 9 faulty DNSSEC signing.
        ##### Remove this and "from subprocess import ..." line once ISC fixes BIND 9.
        origin = z.name.lower()
        path = master.zones[z.name].zfile.path + ".signed"
        cmd = Popen(["dnssec-verify", "-I", "raw", "-z", "-o", origin, path],
                    stdout=PIPE, stderr=PIPE, universal_newlines=True)
        (out, err) = cmd.communicate()
        if cmd.returncode != 0:
            check_log("BIND 9 DNSSEC failure, skipping zone '%s'" % z.name)
            detail_log(" <dnssec-verify>\n" + err.strip())
            detail_log(SEP)
            continue
        ##### End of the workaround.

        slave.zone_verify(z)

t.end()
