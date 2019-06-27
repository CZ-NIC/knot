#!/usr/bin/env python3

'''Test for no re-signing if the zone is properly signed and sync disabled.'''

from dnstest.utils import *
from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")
zone = t.zone("example.com.", storage=".")

master.zonefile_sync = "-1"
slave.zonefile_sync = "0"

t.link(zone, master, slave, ixfr=True)

master.dnssec(zone).enable = True
master.dnssec(zone).nsec3 = True

t.start()

serial = slave.zone_wait(zone)

master.update_zonefile(zone, version=1)
master.reload()

serial = slave.zone_wait(zone, serial)

master.stop()
t.sleep(1)
master.start()

new_serial = master.zone_wait(zone)

if new_serial != serial:
    set_err("zone got re-signed")

slave.zone_wait(zone, new_serial, equal=True, greater=False)
slave.flush()
t.sleep(1)
slave.zone_verify(zone)

t.end()
