#!/usr/bin/env python3

'''Test IXFR-from-diff with DNSSEC'''

from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")
#zones = t.zone_rnd(5, records=150)
zones = t.zone("example.com.")

t.link(zones, master, slave, ixfr=True)

master.semantic_check = False
master.zonefile_sync = "-1"
for zone in zones:
  master.dnssec(zone).enable = True

t.start()

ser1 = master.zones_wait(zones, serials_zfile=True, greater=True, equal=False)
slave.zones_wait(zones, ser1, greater=False, equal=True)

slave.zone_backup(zones, flush=True)

master.flush()
t.sleep(3)
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
