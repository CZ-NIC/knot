#!/usr/bin/env python3

'''Test IXFR-from-diff with DNSSEC'''

from dnstest.test import Test

t = Test(stress=False)

master = t.server("knot")
slave = t.server("knot")

if not master.valgrind:
  zones = t.zone_rnd(12)
else:
  zones = t.zone_rnd(4, records=100)
  slave.tcp_remote_io_timeout = 20000
  master.ctl_params_append = ["-t", "30"]

t.link(zones, master, slave, ixfr=True)

master.semantic_check = False
master.zonefile_sync = "-1"
for zone in zones:
  master.dnssec(zone).enable = True

t.start()

ser1 = master.zones_wait(zones, serials_zfile=True, greater=True, equal=False)
slave.zones_wait(zones, ser1, greater=False, equal=True)

for zone in zones:
  slave.zone_backup(zone, flush=True)

master.flush(wait=True)

for zone in zones:
  master.update_zonefile(zone, random=True)
  master.ctl("zone-reload %s" % zone.name)

ser2 = master.zones_wait(zones, serials_zfile=True, greater=True, equal=False)
slave.zones_wait(zones, ser2, greater=False, equal=True)

master.stop()
t.sleep(3)
master.start()

master.zones_wait(zones, ser2, greater=False, equal=True)

t.xfr_diff(master, slave, zones) # AXFR diff
t.xfr_diff(master, slave, zones, ser1) # IXFR diff

t.end()
