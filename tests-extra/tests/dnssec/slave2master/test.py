#!/usr/bin/env python3

'''Test turning a slave into master and start signing.'''

from dnstest.test import Test
from dnstest.utils import *
import shutil

t = Test()

#zones = t.zone_rnd(1, records=10, dnssec=False)
zones = t.zone("example.com.")

master = t.server("knot")
slave = t.server("knot")

t.link(zones, master, slave, journal_content="all")

for z in zones:
    master.dnssec(z).enable = True
    master.dnssec(z).nsec3 = True

slave.zonefile_load = "difference-no-serial"

t.start()
serials_init = slave.zones_wait(zones)

slave.stop()
master.stop()

for z in zones:
    slave.zones[z.name].masters = set()
# slave becomes a (stand-alone) master
slave.gen_confile()
slave.start()

slave.zones_wait(zones, serials_init, equal=True, greater=False)

slave.stop()
slave_keydir = slave.keydir
shutil.rmtree(slave_keydir)
shutil.copytree(master.keydir, slave_keydir)
# slave starts signing exactly like master used to
for z in zones:
    slave.dnssec(z).enable = master.dnssec(z).enable
    slave.dnssec(z).nsec3 = master.dnssec(z).nsec3
slave.gen_confile()
#slave.reload()
#t.sleep(5)
slave.start()

serials = slave.zones_wait(zones, serials_init, equal=True, greater=False)
up = slave.update(zones[0])
up.add("a", 3600, "A", "1.2.3.4")
up.send("NOERROR")
slave.zones_wait(zones, serials)

t.stop()
