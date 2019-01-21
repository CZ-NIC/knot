#!/usr/bin/env python3

'''Test for no re-signing if the zone is properly signed.'''

from dnstest.utils import *
from dnstest.test import Test

t = Test()

master = t.server("knot")

zone = t.zone("example.com.", storage=".")

t.link(zone, master, ixfr=True, journal_content="all")

master.dnssec(zone).enable = True

t.start()

serial = master.zone_wait(zone)

master.random_ddns(zone, allow_empty=False)

serial = master.zone_wait(zone, serial)

master.stop()
t.sleep(1)
master.start()

new_serial = master.zone_wait(zone)

if new_serial != serial:
    set_err("zone got re-signed")

t.stop()
