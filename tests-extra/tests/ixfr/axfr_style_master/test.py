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

resp_ixfr = knot.dig("example.com", "IXFR", serial=serial_init)

# Query for AXFR for comparison
resp_axfr = knot.dig("example.com", "AXFR")

resp_ixfr.check_axfr_style_ixfr(resp_axfr)

t.end()
