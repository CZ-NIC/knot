#!/usr/bin/env python3

'''Test for changeset application after restart.'''

from dnstest.test import Test
import dnstest.utils

def check_axfr(server, zone):
    # Get AXFR
    axfr_pre = server.dig(zone[0].name, "AXFR", log_no_sep=True)

    # Restart
    server.stop()
    t.sleep(1)
    server.start()
    server.zone_wait(zone)

    # Get AXFR after restart
    axfr_post = server.dig(zone[0].name, "AXFR", log_no_sep=True)

    # Compare AXFRs
    t.axfr_diff_resp(axfr_pre, axfr_post, server, server, zone[0])

t = Test()

master = t.server("knot")
slave = t.server("knot")

# Zone setup
zone = t.zone_rnd(1, dnssec=False)
t.link(zone, master, slave, ixfr=True, ddns=True)

# Turn automatic DNSSEC on
master.dnssec(zone).enable = True
master.dnssec(zone).nsec3 = True

t.start()

# Load zones - master should sign
master.zone_wait(zone)
slave.zone_wait(zone)

# Check DNSSEC application
check_axfr(master, zone)

# Update zone using DDNS
up = master.update(zone)
up.add("test123."+zone[0].name, "3600", "TXT", "test")
up.send("NOERROR")

# Check DDNS application
check_axfr(master, zone)
serial = master.zone_wait(zone)

# Update zonefile on master
master.flush()
t.sleep(1)
master.update_zonefile(zone, random=True)
master.reload()
master.zone_wait(zone)

# Wait for all changes on slave
slave.zone_wait(zone, serial)

# Make sure slave applied everything
check_axfr(slave, zone)

t.end()
