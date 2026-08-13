#!/usr/bin/env python3

'''Test for empty rdata loading.'''

from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")
zone = t.zone("nsec3param.", storage=".")

t.link(zone, master, slave)

master.conf_zone(zone).semantic_checks = False
slave.conf_zone(zone).semantic_checks = False

t.start()

master.zones_wait(zone)
slave.zones_wait(zone)

resp = slave.dig(zone[0].name, "NSEC3PARAM", dnssec=True)
resp.check_count(1, "NSEC3PARAM")

resp = slave.dig("dowiejoiewj." + zone[0].name, "AAAA", dnssec=True)
resp.check(rcode="SERVFAIL")

t.end()
