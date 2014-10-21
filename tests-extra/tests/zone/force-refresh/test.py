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

serials_master = master.zones_wait(zone)
serials_slave = slave.zones_wait(zone)

# Check that the slave's serial is larger than master's
if serials_master["example.com."] >= serials_slave["example.com."]:
	set_err("Master has newer or the same zone as slave.")

# Force refresh
slave.ctl("-f refresh example.com.")

serials_slave = slave.zones_wait(zone)
compare(serials_slave["example.com."], serials_master["example.com."], "Forced refresh")

t.end()
