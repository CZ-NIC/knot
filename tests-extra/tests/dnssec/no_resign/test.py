#!/usr/bin/env python3

'''Test for no resigning if the zone is properly signed.'''

from dnstest.utils import *
from dnstest.test import Test

t = Test()

master = t.server("knot")
nsec_zone = t.zone_rnd(1, dnssec=True, nsec3=False)
nsec3_zone = t.zone_rnd(1, dnssec=True, nsec3=True)
t.link(nsec_zone, master)
t.link(nsec3_zone, master)

t.start()

# Get zone serial.
old_nsec_serial = master.zone_wait(nsec_zone)
old_nsec3_serial = master.zone_wait(nsec3_zone)

# Enable autosigning.
master.dnssec_enable = True
master.use_gen_keys()
master.gen_confile()
master.reload()

t.sleep(4)

new_nsec_serial = master.zone_wait(nsec_zone)
new_nsec3_serial = master.zone_wait(nsec3_zone)

# Check if the zones are resigned.
if compare(old_nsec_serial, new_nsec_serial,
           "%s SOA serial (NSEC)" % nsec_zone[0].name):
    resp = master.dig(nsec_zone, "IXFR", serial=old_nsec_serial)
    for rr in resp.resp:
        detail_log(rr)

if compare(old_nsec3_serial, new_nsec3_serial,
           "%s SOA serial (NSEC3)" % nsec3_zone[0].name):
    resp = master.dig(nsec3_zone, "IXFR", serial=old_nsec3_serial)
    for rr in resp.resp:
        detail_log(rr)

t.stop()
