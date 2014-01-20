#!/usr/bin/env python3

'''Test for transition from NSEC to NSEC3 on auto-signed zone.'''

from dnstest.utils import *
from dnstest.test import Test

t = Test()

master = t.server("knot")
zone = t.zone_rnd(1, dnssec=False)
t.link(zone, master)

t.start()

# Wait for listening server with unsigned zone.
old_serial = master.zone_wait(zone)
master.stop()

# Enable autosigning.
master.dnssec_enable = True
master.gen_key(zone, ksk=True, alg="NSEC3RSASHA1")
master.gen_key(zone, alg="NSEC3RSASHA1")
master.gen_key(zone, ksk=True, alg="RSASHA256")
master.gen_key(zone, alg="RSASHA256")
master.gen_confile()
master.start()

# Wait for changed zone and flush.
new_serial = master.zone_wait(zone, serial=old_serial)
t.sleep(1)
master.flush()
t.sleep(1)

# Check absence of NSEC3PARAM record.
resp = master.dig(zone, "NSEC3PARAM", dnssec=True)
compare(resp.answer_count(), 0, "NSEC3PARAM count")

# Check presence of DNSKEYs.
resp = master.dig(zone, "DNSKEY", dnssec=True)
compare(resp.answer_count(), 4, "DNSKEY count")

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
master.zone_wait(zone, serial=new_serial)
t.sleep(1)
master.flush()
t.sleep(1)

# Check presence of NSEC3PARAM record.
resp = master.dig(zone, "NSEC3PARAM", dnssec=True)
compare(resp.answer_count(), 1, "NSEC3PARAM count")

# Check presence of DNSKEYs.
resp = master.dig(zone, "DNSKEY", dnssec=True)
compare(resp.answer_count(), 4, "DNSKEY count")

# Verify signed zone file.
master.zone_verify(zone)

t.end()
