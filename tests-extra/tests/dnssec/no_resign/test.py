#!/usr/bin/env python3

'''Test for no resigning if the zone is properly signed.'''

from dnstest.utils import *
from dnstest.test import Test

t = Test()

master = t.server("knot")
nsec_zone = t.zone_rnd(1, dnssec=True, nsec3=False)
nsec3_zone = t.zone_rnd(1, dnssec=True, nsec3=True)
static_zone = t.zone("example.", storage=".")
t.link(nsec_zone, master)
t.link(nsec3_zone, master)
t.link(static_zone, master)

t.start()

# Get zone serial.
old_nsec_serial = master.zone_wait(nsec_zone)
old_nsec3_serial = master.zone_wait(nsec3_zone)
old_static_serial = master.zone_wait(static_zone)

# Enable autosigning.
master.dnssec_enable = True
master.use_keys(nsec_zone)
master.use_keys(nsec3_zone)
master.use_keys(static_zone)
master.gen_confile()
t.sleep(2)
master.reload()

t.sleep(4)

new_nsec_serial = master.zone_wait(nsec_zone)
new_nsec3_serial = master.zone_wait(nsec3_zone)
new_static_serial = master.zone_wait(static_zone)

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

if compare(old_static_serial, new_static_serial,
           "%s SOA serial (static)" % static_zone[0].name):
    resp = master.dig(static_zone, "IXFR", serial=old_static_serial)
    for rr in resp.resp:
        detail_log(rr)


# Switch the static zone for the one with different case in records
master.update_zonefile(static_zone, 1)
master.reload()

new_static_serial2 = master.zone_wait(static_zone)

if compare(new_static_serial, new_static_serial2,
           "%s SOA serial (static)" % static_zone[0].name):
    resp = master.dig(static_zone, "IXFR", serial=new_static_serial)
    for rr in resp.resp:
        detail_log(rr)

# Switch the static zone again, this time change case in NSEC only
# Zone should be resigned, as the NSEC's RRSIG is no longer valid
master.update_zonefile(static_zone, 2)
master.reload()

new_static_serial3 = master.zone_wait(static_zone)

# How to check that they are different??
#compare(new_static_serial2, new_static_serial3,
#        "%s SOA serial (static, NSEC change)" % static_zone[0].name);

master.zone_verify(static_zone)

t.stop()
