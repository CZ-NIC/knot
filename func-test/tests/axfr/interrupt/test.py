#!/usr/bin/env python3

'''Test for Knot clean-up after interruption of AXFR from Bind'''

import dnstest

t = dnstest.DnsTest()

master = t.server("bind")
slave = t.server("knot")
zones = t.zone_rnd(1, dnssec=False, records=50000)

t.link(zones, master, slave)

t.start()

t.sleep(2)
dnstest.check_log("Killing master %s" % master.name)
master.proc.kill()
t.sleep(5)

t.end()
