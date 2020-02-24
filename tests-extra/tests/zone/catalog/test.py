#!/usr/bin/env python3

'''Test of Catalog zones.'''

from dnstest.test import Test
from dnstest.utils import set_err, detail_log

import glob
import shutil

t = Test()

master = t.server("knot")
slave = t.server("knot")

# Zone setup
zone = t.zone("example.com.") + t.zone("catalog1.", storage=".")# + t.zone("catalog2.", storage=".")

t.link(zone, master, slave, ixfr=True)

master.zones["catalog1."].catalog = True
slave.zones["catalog1."].catalog = True

for zf in glob.glob(t.data_dir + "/*.zone"):
    shutil.copy(zf, master.dir + "/master")

t.start()

# Basic: master a slave configure cataloged zone.
t.sleep(2)
resp = master.dig("cataloged1.", "SOA")
resp.check(rcode="NOERROR")
resp = slave.dig("cataloged1.", "SOA")
resp.check(rcode="NOERROR")

# Check adding cataloged zone.
up = master.update(zone[1])
up.add("bar.catalog1.", 3600, "PTR", "cataloged2.")
up.send("NOERROR")
t.sleep(2)
resp = master.dig("cataloged2.", "NS")
resp.check(rcode="NOERROR")
resp = slave.dig("cataloged2.", "NS")
resp.check(rcode="NOERROR")


# Check inaccessibility of catalog zone
slave.ctl("conf-begin")
slave.ctl("conf-unset zone[catalog1.].acl")
slave.ctl("conf-commit")
t.sleep(1)
resp = slave.dig("abc.catalog1.", "A")
resp.check(rcode="REFUSED")

t.end()
