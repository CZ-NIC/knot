#!/usr/bin/env python3

'''Test that removal of nonexistent record is not promoted to IXFR'''

from dnstest.test import Test
from dnstest.utils import *

t = Test()

master = t.server("knot")
slave = t.server("knot")

zone = t.zone("existing.", storage=".")

t.link(zone, master, slave, ixfr=True)

# Add the record from slave zone file (no SOA serial change).
slave.update_zonefile(zone, version=1)

t.start()

serial = master.zone_wait(zone)
slave.zone_wait(zone)

up = master.update(zone)
up.add("abc.existing.", 3600, "AAAA", "1::2")
up.delete("onlyslave.existing.", "A", "100.0.0.1")
up.delete("onlyslave.existing.", "A", "1.2.3.4")
up.send()

#master.ctl("zone-begin existing.")
#master.ctl("zone-set existing. abc.existing. 3600 AAAA 1::2")
#master.ctl("zone-unset existing. onlyslave.existing. A 100.0.0.1")
#master.ctl("zone-unset existing. onlyslave.existing. A 1.2.3.4") # this one shall fail
#master.ctl("zone-commit existing.")

slave.zone_wait(zone, serial)

resp = slave.dig("onlyslave.existing.", "A")
resp.check(rcode="NOERROR", rdata="1.2.3.4")

t.end()
