#!/usr/bin/env python3

'''Test for unsuccessful creation of NSEC3 tree'''

from dnstest.test import Test

t = Test()

master = t.server("knot")
zone = t.zone_rnd(1, records=200)

t.link(zone, master)

master.journal_max_usage = 51200 # the creation of NSEC3 tree fails on ESPACE

t.start()
master.zone_wait(zone)

master.dnssec(zone).enable = True
master.dnssec(zone).nsec3 = True
master.gen_confile()
master.reload()

t.sleep(8) # unfixed knotd will crash upon update reversal
master.flush(wait=True)

t.end()
