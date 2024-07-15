#!/usr/bin/env python3

'''Test of DDNS over TLS using DNSKEY-sync feature.'''

import random
from dnstest.test import Test
from dnstest.keys import Tsig

def check_dnskey(a, b, zones):
    for z in zones:
        q_a = a.dig(z.name, "DNSKEY", dnssec=False)
        q_b = b.dig(z.name, "DNSKEY", dnssec=False)
        q_a.diff(q_b)

key = Tsig() if random.choice([True, False]) else False
t = Test(tls=True, tsig=key)

sender = t.server("knot", tsig=key, xdp_enable=False)
recver = t.server("knot", tsig=key, xdp_enable=False)
zones = t.zone("catalog.") # zero TTL -> faster roll-over

t.link(zones, sender)
t.link(zones, recver, ddns=True)

for z in zones:
    sender.dnssec(z).enable = True
    sender.dnssec(z).propagation_delay = 4
    sender.dnssec(z).dnskey_sync = [ recver ]

t.start()

s_sender = sender.zones_wait(zones)
for z in zones:
    sender.ctl("zone-ksk-submitted " + z.name) # speedup DNSKEY sync re-try
t.sleep(5)
s_sender = sender.zones_wait(zones)
s_recver = recver.zones_wait(zones)

check_dnskey(sender, recver, zones)

recver.ctl("zone-freeze", wait=True)
for z in zones:
    sender.ctl("zone-key-rollover %s zsk" % z.name)

# ZSK roll changes zone 3x, all DDNSs queued
s_sender = sender.zones_wait(zones, s_sender)
s_sender = sender.zones_wait(zones, s_sender)
s_sender = sender.zones_wait(zones, s_sender)

recver.ctl("zone-thaw", wait=True)
s_recver = recver.zones_wait(zones, s_recver)
check_dnskey(sender, recver, zones)

t.end()
