#!/usr/bin/env python3

'''Test of min/max limit of SOA params (refresh, retry, expire)'''

from dnstest.test import Test
import time

t = Test()

master = t.server("knot")
slave = t.server("knot")
zone_min_ = t.zone("min.", storage=".")
zone_max_ = t.zone("max.", storage=".")
zone_min = zone_min_[0]
zone_max = zone_max_[0]
zones = zone_min_ + zone_max_

t.link(zones, master, slave, ixfr=True)

master.disable_notify = True
slave.disable_notify = True

slave.zones[zone_min.name].refresh_min = 12
slave.zones[zone_max.name].refresh_max = 9
slave.zones[zone_min.name].retry_min = 12
slave.zones[zone_max.name].retry_max = 9
slave.zones[zone_min.name].expire_min = 24
slave.zones[zone_max.name].expire_max = 18

t.start()

# Wait for AXFR to slave server.
serials_init = master.zones_wait(zones)
slave.zones_wait(zones)

slave.ctl("zone-refresh")

up = master.update(zone_max_)
up.add("added", 3600, "A", "1.2.3.4")
up.send()
up = master.update(zone_min_)
up.add("added", 3600, "A", "1.2.3.4")
up.send()

t.sleep(10)

# chech that MAX already refreshed and MIN has not

resp = slave.dig(zone_max.name, "SOA")
resp.check_soa_serial(serials_init[zone_max.name] + 1)
resp = slave.dig(zone_min.name, "SOA")
resp.check_soa_serial(serials_init[zone_min.name])

master.stop()
slave.ctl("zone-refresh")

retry_start = time.time()
t.sleep(1)
master.update_zonefile(zone_max, version=10)
master.update_zonefile(zone_min, version=10)
master.start()
master.zones_wait(zones)
try:
    t.sleep(10 - (time.time() - retry_start))
except: # negative sleep
    pass

resp = slave.dig(zone_max.name, "SOA")
resp.check_soa_serial(serials_init[zone_max.name] + 10)
resp = slave.dig(zone_min.name, "SOA")
resp.check_soa_serial(serials_init[zone_min.name])

slave.ctl("zone-refresh")
t.sleep(2)
master.stop()

t.sleep(18)

resp = slave.dig(zone_max.name, "SOA")
resp.check(rcode="SERVFAIL")
resp = slave.dig(zone_min.name, "SOA")
resp.check(rcode="NOERROR")

t.end()
