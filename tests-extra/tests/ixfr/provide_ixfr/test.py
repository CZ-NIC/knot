#!/usr/bin/env python3

'''Test for AXFR-style IXFR controlled by provide-ixfr configuration'''

from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")
zone = t.zone("example.com")

t.link(zone, master, slave, ixfr=True)

t.start()

serial_init = master.zones_wait(zone)

# Update the zone to create some history.
master.update_zonefile(zone, random=True)
master.reload()
slave.zones_wait(zone, serial_init)

# Disable IXFR and check AXFR-style IXFR.
master.provide_ixfr = False
master.gen_confile()
master.reload()
master.zones_wait(zone, serial_init)

t.check_axfr_style_ixfr(master, zone[0].name, serial_init[zone[0].name])

# Enable IXFR and compare with slave.
master.provide_ixfr = True
master.gen_confile()
master.reload()
master.zones_wait(zone, serial_init)

t.xfr_diff(master, slave, zone, serial_init)

t.stop()
