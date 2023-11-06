#!/usr/bin/env python3

'''Test of DDNS over QUIC.'''

import random
from dnstest.test import Test
from dnstest.keys import Tsig

def check_dnskey(a, b, zones):
    for z in zones:
        q_a = a.dig(z.name, "DNSKEY", dnssec=False)
        q_b = b.dig(z.name, "DNSKEY", dnssec=False)
        q_a.diff(q_b)

key = Tsig() if random.choice([True, False]) else False
t = Test(quic=True, tsig=key)

sender = t.server("knot", tsig=key, xdp_enable=False)
recver = t.server("knot", tsig=key, xdp_enable=False)
zones = t.zone("catalog.") # zero TTL -> faster roll-over

t.link(zones, sender)
t.link(zones, recver, ddns=True)

for z in zones:
    sender.dnssec(z).enable = True
    sender.dnssec(z).propagation_delay = 4
    sender.dnssec(z).dnskey_sync = [ recver ]

sender.check_quic()

t.start()

s_sender = sender.zones_wait(zones)
for z in zones:
    sender.ctl("zone-ksk-submitted " + z.name) # speedup DNSKEY sync re-try
s_recver = recver.zones_wait(zones, s_sender, equal=True) # DDNS from sender should increment the serial to equal sender after first signing

check_dnskey(sender, recver, zones)

s_sender = sender.zones_wait(zones) # update s_sender to match current state
recver.ctl("zone-freeze")
for z in zones:
    sender.ctl("zone-key-rollover %s zsk" % z.name)

# ZSK roll changes zone 3x, all DDNSs queued
s_sender = sender.zones_wait(zones, s_sender)
s_sender = sender.zones_wait(zones, s_sender)
s_sender = sender.zones_wait(zones, s_sender)

recver.ctl("zone-thaw")
s_recver = recver.zones_wait(zones, s_recver)
check_dnskey(sender, recver, zones)

t.end()
