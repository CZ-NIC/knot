#!/usr/bin/env python3

'''Test for transition from NSEC to NSEC3 on auto-signed zone.'''

from dnstest.utils import *
from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("bind")
zone = t.zone_rnd(1, dnssec=False)
t.link(zone, master, slave)

t.start()

# Wait for listening server with unsigned zone.
old_serial = master.zone_wait(zone)
slave.zone_wait(zone)
t.xfr_diff(master, slave, zone)

# Check NSEC absence.
master.check_nsec(zone, nonsec=True)

master.stop()

# Enable autosigning.
master.dnssec_enable = True
master.gen_key(zone, ksk=True, alg="rsasha1-nsec3-sha1")
master.gen_key(zone, alg="rsasha1-nsec3-sha1")
master.gen_key(zone, ksk=True, alg="rsasha256")
master.gen_key(zone, alg="rsasha256")
master.gen_confile()
master.start()

# Wait for changed zone and flush.
new_serial = master.zone_wait(zone, old_serial)
slave.zone_wait(zone, old_serial)
t.xfr_diff(master, slave, zone)
master.flush()
t.sleep(1)

# Check absence of NSEC3PARAM record.
resp = master.dig(zone, "NSEC3PARAM", dnssec=True)
compare(resp.count(), 0, "NSEC3PARAM count")

# Check presence of DNSKEYs.
resp = master.dig(zone, "DNSKEY", dnssec=True)
compare(resp.count(), 4, "DNSKEY count")

# Check NSEC presence.
master.check_nsec(zone)

master.stop()
master.backup_zone(zone)

# Verify signed zone file.
master.zone_verify(zone)

### NSEC -> NSEC3 ###

# Enable NSEC3 on zone.
master.enable_nsec3(zone)
master.gen_confile()
master.start()

# Wait for changed zone and flush.
master.zone_wait(zone, new_serial)
slave.zone_wait(zone, new_serial)
t.xfr_diff(master, slave, zone)
master.flush()
t.sleep(1)

# Check presence of NSEC3PARAM record.
resp = master.dig(zone, "NSEC3PARAM", dnssec=True)
compare(resp.count(), 1, "NSEC3PARAM count")

# Check presence of DNSKEYs.
resp = master.dig(zone, "DNSKEY", dnssec=True)
compare(resp.count(), 4, "DNSKEY count")

# Check NSEC3 presence.
master.check_nsec(zone, nsec3=True)

# Verify signed zone file.
master.zone_verify(zone)

t.end()
