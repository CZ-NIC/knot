#!/usr/bin/env python3

'''Test that removal of nonexisting or addition of existing record over CTL
is not promoted to IXFR'''

from dnstest.test import Test
from dnstest.utils import *

t = Test()

master = t.server("knot")
slave = t.server("knot")

zone = t.zone("existing.", storage=".")

t.link(zone, master, slave, ixfr=True)

# Prepare different zone contents on the slave (no SOA serial change)
slave.update_zonefile(zone, version=1)

t.start()

serial = master.zone_wait(zone)
slave.zone_wait(zone)

# Check that removal of nonexisting record is not promoted

master.ctl("zone-begin existing.")
master.ctl("zone-unset existing. onlyslave.existing. A 100.0.0.1")
try:
    master.ctl("zone-unset existing. onlyslave.existing. A 1.2.3.4")
except Failed:
    pass
else:
    detail_log("removal of nonexisting record not refused")
    set_err("CTL ERROR")
master.ctl("zone-commit existing.")

serial = slave.zone_wait(zone, serial)
resp = slave.dig("onlyslave.existing.", "A")
resp.check(rcode="NOERROR", rdata="1.2.3.4")

# Check that addition of existing record is not promoted

master.ctl("zone-begin existing.")
master.ctl("zone-set existing. onlymaster.existing. 3600 TXT new_text")
try:
    master.ctl("zone-set existing. onlymaster.existing. 3600 TXT text")
except Failed:
    pass
else:
    detail_log("addition of existing record not refused")
    set_err("CTL ERROR")
master.ctl("zone-commit existing.")

slave.zone_wait(zone, serial)
resp = slave.dig("onlymaster.existing.", "TXT")
resp.check(rcode="NOERROR", rdata="new_text")
resp.check(rcode="NOERROR", nordata="text")

t.end()
