#!/usr/bin/env python3

'''Test for changeset application after restart. '''

from dnstest.test import Test
import dnstest.utils

t = Test()

master = t.server("knot")
slave = t.server("knot")

# Zone setup
zone = t.zone_rnd(1)

t.link(zone, master, slave, ixfr = True)

t.start()

# Load zones - master should sign
serial = master.zone_wait(zone)
slave.zone_wait(zone)

# Get AXFR from master
axfr_pre = master.dig(zone[0].name, "AXFR", log_no_sep=True)

# Restart and compare AXFRs
master.stop()

master.start()
master.zone_wait(zone)

axfr_post = master.dig(zone[0].name, "AXFR", log_no_sep=True)

t.axfr_diff_resp(axfr_pre, axfr_post, zone[0])

# Update zonefile on master

# Wait for changes on slave

# Restart and do an AXFR diff

# Update zone using DDNS

# Stop and start, do an AXFR diff

# Stop and start the slave server, make sure everything is applied

master.stop()
slave.stop()

t.end()
