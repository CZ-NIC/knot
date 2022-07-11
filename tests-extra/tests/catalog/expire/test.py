#!/usr/bin/env python3

'''Test of Interpreted Catalog zone (non-)expiration.'''

from dnstest.test import Test

import glob
import os
import shutil

t = Test()

master = t.server("knot")
slave = t.server("knot")

# Zones setup
zone = t.zone("catalog1.", storage=".")
members = t.zone("cataloged1.", storage=".")

t.link(zone, master, slave, ixfr=True)

master.cat_interpret(zone[0])
slave.cat_interpret(zone[0])

os.mkdir(master.dir + "/catalog")
for zf in glob.glob(t.data_dir + "/*.zone"):
    shutil.copy(zf, master.dir + "/catalog")

t.start()

slave.zones_wait(members)
master.stop() # even regular answers must be blocked (to prevent refresh)

# Check non-expiration of catalog.
t.sleep(4)  # greater than the SOA expire
resp = slave.dig("catalog1.", "SOA", udp=False, tsig=True)
resp.check(rcode="NOERROR")
resp = slave.dig("cataloged1.", "SOA", udp=False, tsig=True)
resp.check(rcode="NOERROR")

# Check regular expiration of member zones.
t.sleep(5)  # together with previous sleep greater than members expire
resp = slave.dig("catalog1.", "SOA", udp=False, tsig=True)
resp.check(rcode="NOERROR")
resp = slave.dig("cataloged1.", "SOA", udp=False, tsig=True)
resp.check(rcode="SERVFAIL")

master.start()
slave.ctl("zone-refresh") # don't waste time waiting for member bootstrap
slave.zones_wait(members)

# Check manual expiration of catalog.
master.ctl("zone-purge -f +expire %s" % zone[0].name, wait=True)
slave.ctl("zone-purge -f +expire %s" % zone[0].name, wait=True)
resp = master.dig("catalog1.", "SOA", udp=False, tsig=True)
resp.check(rcode="SERVFAIL")
resp = slave.dig("catalog1.", "SOA", udp=False, tsig=True)
resp.check(rcode="SERVFAIL")
# State of members after a catalog expire isn't standardised yet.
# Add a check for it in the future.

t.end()
