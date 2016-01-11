#!/usr/bin/env python3

'''Test for reload of a changed zone (serial up, nochange, serial down). '''

from dnstest.test import Test
from dnstest.utils import *

t = Test()

master = t.server("bind")
slave = t.server("knot")

zone = t.zone("example.com.", storage=".")
t.link(zone, master, slave)

# Load newer zone to the slave
slave.update_zonefile(zone, version=1)

t.start()

serial_master = master.zone_wait(zone)
serial_slave = slave.zone_wait(zone)

# Check that the slave's serial is larger than master's
assert serial_master <= serial_slave

# Force refresh
slave.ctl("zone-retransfer example.com.")
t.sleep(2)

serial_slave = slave.zone_wait(zone)
compare(serial_slave, serial_master, "Serial after retransfer")

t.end()
