#!/usr/bin/env python3

'''Test for fallback IXFR->AXFR with Knot master'''

from dnstest.test import Test

t = Test()

knot = t.server("knot")
zone = t.zone("example.com.", storage=".")

t.link(zone, knot, ixfr=False)

t.start()

# Wait for AXFR to slave server.
serial_init = knot.zone_wait(zone)

# 2nd version of the zone, differing only in serial, so that there is quite
# a difference between AXFR and IXFR
knot.update_zonefile(zone, 1)
knot.reload()

# Check if IXFR gives answer in the format of AXFR
t.check_axfr_style_ixfr(knot, "example.com.", serial_init)

t.end()
