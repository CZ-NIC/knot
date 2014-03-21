#!/usr/bin/env python3

'''Test for properly signed NSEC/NSEC3 zone '''

from dnstest.utils import *
from dnstest.test import Test

t = Test()

master = t.server("knot")
nsec_zone = t.zone_rnd(1, dnssec=True, nsec3=False)
nsec3_zone = t.zone_rnd(1, dnssec=True, nsec3=True)
t.link(nsec_zone, master)
t.link(nsec3_zone, master)

t.start()

check_log("Load signed zones")
# Get zone serial.
old_nsec_serial = master.zone_wait(nsec_zone)
old_nsec3_serial = master.zone_wait(nsec3_zone)

# Enable autosigning.
master.dnssec_enable = True
master.use_gen_keys()
master.gen_confile()
check_log("Add keys for zones")
master.reload()

t.sleep(3)

new_nsec_serial = master.zone_wait(nsec_zone)
new_nsec3_serial = master.zone_wait(nsec3_zone)

compare(old_nsec_serial, new_nsec_serial, "Server did needless NSEC signing operation")
compare(old_nsec3_serial, new_nsec3_serial, "Server did needless NSEC3 signing operation")

t.stop()
