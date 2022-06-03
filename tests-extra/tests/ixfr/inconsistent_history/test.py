#!/usr/bin/env python3

'''Test for failed IXFR with inconsistent history'''

from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")
zone = t.zone("example.com.", storage=".")
t.link(zone, master, slave, ixfr=True)

master.disable_notify = True
slave.disable_notify = True

t.start()

# Start both servers with the initial zone
serial = master.zone_wait(zone)
slave.zone_wait(zone)

# Add some zone history on the master only
master.update_zonefile(zone, version=1)
master.reload()
serial = master.zone_wait(zone, serial)

# Update the zone in a wrong way (zonefile-load: difference, journal-contents: changes, restart)
# -> missing a changeset in the journal
master.update_zonefile(zone, version=2)
master.stop()
master.start()

# Try to refresh slave, IXFR should fail, AXFR ok
slave.ctl("zone-refresh", wait=True)

master.zone_wait(zone, serial)
slave.zone_wait(zone, serial)

# Check that slave has the actual zone
resp = slave.dig("dns1.example.com.", "A")
resp.check()
resp.check_record(name="dns1.example.com.", rtype="A", rdata="192.0.2.3")

t.end()
