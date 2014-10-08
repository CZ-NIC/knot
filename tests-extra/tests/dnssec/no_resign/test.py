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
t.sleep(1)
master.reload()

t.sleep(4)

new_nsec_serial = master.zone_wait(nsec_zone)
new_nsec3_serial = master.zone_wait(nsec3_zone)
new_static_serial = master.zone_wait(static_zone)

# Check if the zones are resigned.
compare(old_nsec_serial, new_nsec_serial, "NSEC zone got resigned")
compare(old_nsec3_serial, new_nsec3_serial, "NSEC3 zone got resigned")
compare(old_static_serial, new_static_serial, "static zone got resigned")

prev_serial = new_static_serial

# Switch the static zone for the one with different case in records
master.update_zonefile(static_zone, 1)
master.reload()

serial = master.zone_wait(static_zone)

compare(prev_serial, serial, "static zone got resigned after case change")

# Switch the static zone again, this time change case in NSEC only
# Zone should be resigned, as the NSEC's RRSIG is no longer valid
master.update_zonefile(static_zone, 2)
master.reload()

serial = master.zone_wait(static_zone)

if (serial <= prev_serial):
    set_err("Ignored NSEC change")

master.zone_verify(static_zone)

t.stop()
