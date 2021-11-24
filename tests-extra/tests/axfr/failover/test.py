#!/usr/bin/env python3

"""
Multi-master failover tests.
"""

from dnstest.test import Test

t = Test()

# testing zone
zone = t.zone_rnd(1, dnssec=False, records=1)[0]
zone.update_soa(serial=1, refresh=600, retry=600, expire=3600)

# +---------+       +---------+
# | master1 <-------+ master2 |
# +----^----+       +----^----+
#      |                 |    
#      |   +---------+   |    
#      +---+  slave  +---+    
#          +---------+   

master1 = t.server("knot")
master2 = t.server("knot")
slave = t.server("knot")

# flush zones immediately
for server in [master1, master2, slave]:
    slave.zonefile_sync = "0"

t.link([zone], master1, master2)
t.link([zone], master1, slave)
t.link([zone], master2, slave)

slave.journal_db_size = 1024 * 1024
slave.zones[zone.name].journal_content = "all"

t.start()

# zone bootstrap
for server in [master1, master2, slave]:
    server.zone_wait(zone)

# transfer with fully working topology
master1.zones[zone.name].zfile.update_soa(serial=10)
master1.reload()
for server in [master1, master2, slave]:
    server.zone_wait(zone, serial=10, equal=True, greater=False)

# stop slave, update masters
slave.stop()
master1.zones[zone.name].zfile.update_soa(serial=20)
master1.reload()
for server in [master1, master2]:
    server.zone_wait(zone, serial=20, equal=True, greater=False)

# failover to second master
master1.stop()
slave.clean(zone=False, timers=True)
slave.start()
slave.zone_wait(zone, serial=20, equal=True, greater=False)
master1.start()

# stop slave, update masters
slave.stop()
master1.zones[zone.name].zfile.update_soa(serial=30)
master1.reload()
for server in [master1, master2]:
    server.zone_wait(zone, serial=30, equal=True, greater=False)

# failover after notify
master1.stop()
master2.stop()
slave.start()
slave.zone_wait(zone, serial=20, equal=True, greater=False)
master2.start()
slave.zone_wait(zone, serial=30, equal=True, greater=False)

# don't failover on local error
# the local error will be journal DB size
master2.stop()
first_master = slave.first_master(zone.name)
for i in range(5000):
    first_master.zones[zone.name].zfile.append_rndTXT("txt%d." % i + zone.name, rdlen=255) # this will exceed the size on preferred master
master1.zones[zone.name].zfile.update_soa(serial=40)
master2.zones[zone.name].zfile.update_soa(serial=40) # equal serial, different contents
slave.stop()
master1.start()
master2.start()
t.sleep(4)
slave.start()
slave.ctl("zone-refresh")
t.sleep(8)
slave.zone_wait(zone, serial=30, equal=True, greater=False) # serial 40 from first_master failed on EZONESIZE, and serial 40 from the other master was not attempted

t.end()
