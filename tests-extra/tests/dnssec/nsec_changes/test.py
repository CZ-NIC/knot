#!/usr/bin/env python3

'''Test for NSEC transitions with autosigning.
   zone1: none->nsec->nsec3_params1->nsec3_params2->none
   zone2: none->nsec3_params2->nsec3_params1->nsec->none'''

from dnstest.utils import *
from dnstest.test import Test

def check_salt(server, zone):
  expect_salt_len = server.dnssec(zone).nsec3_salt_len * 2 # *2 because we get hex string
  if expect_salt_len == 0:
      expect_salt_len = 1 # there will be a dash

  resp = server.dig("dijewdjjdljewdew." + zone[0].name, "A", dnssec=True)
  resp.check(rcode="NXDOMAIN")
  nsec3 = resp.resp.authority[1].to_rdataset()
  fields = nsec3.to_text().split()
  if fields[2] != "NSEC3":
      set_err("NO NSEC3")
  elif len(fields[6]) != expect_salt_len:
      set_err("Wrong NSEC3 salt_length: %d not %d" % (len(fields[6]), expect_salt_len))

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
master.flush(wait=True)

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

check_salt(master, zone2)

# Verify signed zone files.
master.zone_verify(zone1)
master.zone_verify(zone2)

### Second change #############################################################

# Reconfigure autosigning.
master.dnssec(zone1).nsec3 = True
master.dnssec(zone1).nsec3_iters = 2
master.dnssec(zone1).nsec3_salt_len = 2
master.dnssec(zone2).nsec3 = True
master.dnssec(zone2).nsec3_iters = 1
master.dnssec(zone2).nsec3_salt_len = 0
master.gen_confile()
# Intentionally restarted to ensure the zone file is fully loaded.
master.stop()
master.start()

# Wait for changed zone and flush.
master.zones_wait(zones, old_serials)
old_serials = slave.zones_wait(zones, old_serials)
t.xfr_diff(master, slave, zones)
master.flush(wait=True)

# Check the NSEC3PARAM record.
resp = master.dig(zone1, "NSEC3PARAM", dnssec=True)
compare(resp.count(), 1, "NSEC3PARAM count")
resp = master.dig(zone2, "NSEC3PARAM", dnssec=True)
compare(resp.count(), 1, "NSEC3PARAM count")

# Check DNSKEYs.
resp = master.dig(zone1, "DNSKEY", dnssec=True)
compare(resp.count(), 2, "DNSKEY count")
resp = master.dig(zone2, "DNSKEY", dnssec=True)
compare(resp.count(), 2, "DNSKEY count")

# Check NSEC.
master.check_nsec(zone1, nsec3=True)
master.check_nsec(zone2, nsec3=True)

check_salt(master, zone1)
check_salt(master, zone2)

# Verify signed zone files.
master.zone_verify(zone1)
master.zone_verify(zone2)

### Third change ##############################################################

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
master.flush(wait=True)

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

check_salt(master, zone1)

# Verify signed zone files.
master.zone_verify(zone1)
master.zone_verify(zone2)

### Fourth change #############################################################

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
master.flush(wait=True)

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
