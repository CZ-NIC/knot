#!/usr/bin/env python3

'''Test for signing a zone with weird records.'''

from dnstest.utils import *
from dnstest.test import Test

t = Test()

master = t.server("knot")
zone = t.zone("records.")
t.link(zone, master)
master.dnssec(zone).enable = True

t.start()

master.zone_wait(zone)

resp = master.dig("nxdomain.records", "A", udp=False, dnssec=True)
resp.check_auth_soa_ttl(dnssec=True)

resp = master.dig("mail.records.", "RRSIG", dnssec=True)
resp.check_count(1, rtype="RRSIG")

t.sleep(1)
master.flush(wait=True)

# Verify signed zone file.
master.zone_verify(zone)

t.stop()
