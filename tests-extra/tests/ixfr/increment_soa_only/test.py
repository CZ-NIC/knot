#!/usr/bin/env python3

'''Check that only-SOA-serial-incremented zone file change is correctly detected and signed.'''

from dnstest.test import Test

t = Test()

knot = t.server("knot")
zone = t.zone("example.com")[0]

t.link([zone], knot, ixfr=True)

knot.dnssec(zone).enable = True

t.start()

serial = knot.zone_wait(zone)
knot.flush(zone, wait=True)
knot.zone_verify(zone)

knot.zones[zone.name].zfile.update_soa(serial=int(serial)+1)
knot.reload()

knot.zone_wait(zone, serial)
knot.flush(zone, wait=True)
knot.zone_verify(zone)

t.end()
