#!/usr/bin/env python3

'''Test for NSEC transitions with autosigning.
   zone1: none->nsec->nsec3->none
   zone2: none->nsec3->nsec->none'''

from dnstest.utils import *
from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("bind")
zone1 = t.zone_rnd(1, dnssec=False, records=5)
zone2 = t.zone_rnd(1, dnssec=False, records=5)
zones = zone1 + zone2
t.link(zones, master, slave)

t.start()

# Wait for listening server with unsigned zones.
master.zones_wait(zones)
old_serials = slave.zones_wait(zones)
t.xfr_diff(master, slave, zones)

# Check NSEC absence.
master.check_nsec(zone1, nonsec=True)
master.check_nsec(zone2, nonsec=True)

### First change ##############################################################

# Enable autosigning.
master.dnssec(zone1).enable = True
master.dnssec(zone2).enable = True
master.dnssec(zone2).nsec3 = True
master.dnssec(zone2).nsec3_iters = 2
master.dnssec(zone2).nsec3_salt_len = 2
master.gen_confile()
master.reload()

# Wait for changed zone and flush.
master.zones_wait(zones, old_serials)
old_serials = slave.zones_wait(zones, old_serials)
t.xfr_diff(master, slave, zones)
master.flush()
t.sleep(1)

# Check the NSEC3PARAM record.
resp = master.dig(zone1, "NSEC3PARAM", dnssec=True)
compare(resp.count(), 0, "NSEC3PARAM count")
resp = master.dig(zone2, "NSEC3PARAM", dnssec=True)
compare(resp.count(), 1, "NSEC3PARAM count")

# Check DNSKEYs.
resp = master.dig(zone1, "DNSKEY", dnssec=True)
compare(resp.count(), 2, "DNSKEY count")
resp = master.dig(zone2, "DNSKEY", dnssec=True)
compare(resp.count(), 2, "DNSKEY count")

# Check NSEC.
master.check_nsec(zone1)
master.check_nsec(zone2, nsec3=True)

# Verify signed zone files.
master.zone_verify(zone1)
master.zone_verify(zone2)

### Second change #############################################################

# Reconfigure autosigning.
master.dnssec(zone1).nsec3 = True
master.dnssec(zone1).nsec3_iters = 1
master.dnssec(zone1).nsec3_salt_len = 0
master.dnssec(zone2).nsec3 = False
master.gen_confile()
master.reload()

# Wait for changed zone and flush.
master.zones_wait(zones, old_serials)
old_serials = slave.zones_wait(zones, old_serials)
t.xfr_diff(master, slave, zones)
master.flush()
t.sleep(1)

# Check the NSEC3PARAM record.
resp = master.dig(zone1, "NSEC3PARAM", dnssec=True)
compare(resp.count(), 1, "NSEC3PARAM count")
resp = master.dig(zone2, "NSEC3PARAM", dnssec=True)
compare(resp.count(), 0, "NSEC3PARAM count")

# Check DNSKEYs.
resp = master.dig(zone1, "DNSKEY", dnssec=True)
compare(resp.count(), 2, "DNSKEY count")
resp = master.dig(zone2, "DNSKEY", dnssec=True)
compare(resp.count(), 2, "DNSKEY count")

# Check NSEC.
master.check_nsec(zone1, nsec3=True)
master.check_nsec(zone2)

# Verify signed zone files.
master.zone_verify(zone1)
master.zone_verify(zone2)

### Third change ##############################################################

# Disable autosigning.
master.dnssec(zone1).enable = False
master.dnssec(zone2).enable = False
master.gen_confile()
master.reload()

# Wait for changed zone and flush (unchanged).
t.sleep(1)
master.zones_wait(zones, old_serials, equal=True, greater=False)
slave.zones_wait(zones, old_serials, equal=True, greater=False)
t.xfr_diff(master, slave, zones)
master.flush()
t.sleep(1)

# Check the NSEC3PARAM record (unchanged).
resp = master.dig(zone1, "NSEC3PARAM", dnssec=True)
compare(resp.count(), 1, "NSEC3PARAM count")
resp = master.dig(zone2, "NSEC3PARAM", dnssec=True)
compare(resp.count(), 0, "NSEC3PARAM count")

# Check DNSKEYs (unchanged).
resp = master.dig(zone1, "DNSKEY", dnssec=True)
compare(resp.count(), 2, "DNSKEY count")
resp = master.dig(zone2, "DNSKEY", dnssec=True)
compare(resp.count(), 2, "DNSKEY count")

# Check NSEC (unchanged).
master.check_nsec(zone1, nsec3=True)
master.check_nsec(zone2)

# Verify signed zone files (unchanged).
master.zone_verify(zone1)
master.zone_verify(zone2)

t.end()
