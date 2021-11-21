#!/usr/bin/env python3

"""
Check of automatic ZSK rollover with changing zone TTLs.
"""

from dnstest.utils import *
from dnstest.test import Test

def dnskey_count(server, zone):
    return server.dig(zone[0].name, "DNSKEY", dnssec=False).count("DNSKEY")

def zsk_keytag(server, zone):
    resp = server.dig(zone[0].name, "SOA", dnssec=True)
    if resp.count("RRSIG") < 1:
        return -1
    elif resp.count("RRSIG") > 1:
        return -2

    rrsig = resp.resp.answer[1].to_rdataset()[0].to_text()
    return rrsig.split()[6]

def wait4key(t, server, zone, dnskeys, not_keytag, min_wait, max_wait, step):
    waited = 0
    while waited < max_wait:
        if dnskey_count(server, zone) == dnskeys and zsk_keytag(server, zone) != not_keytag:
            break
        
        t.sleep(1)
        waited += 1

    if waited < min_wait:
        set_err("%s too early" % step)
        detail_log("%s too early: %d < %d" % (step, waited, min_wait))
    if waited >= max_wait:
        set_err("%s failed" % step)
    detail_log(SEP)

t = Test()

master = t.server("knot")
zone = t.zone("example.com.", storage=".")
t.link(zone, master, ddns=True)

master.dnssec(zone).enable = True
master.dnssec(zone).manual = False
master.dnssec(zone).dnskey_ttl = 3
master.dnssec(zone).zsk_lifetime = 16
master.dnssec(zone).propagation_delay = 3

t.start()
wait4key(t, master, zone, 3, -1, 6, 20, "ZSK publish") # new ZSK published
old_key = zsk_keytag(master, zone)

wait4key(t, master, zone, 3, old_key, 4, 8, "ZSK switch") # active ZSK switched
up = master.update(zone)
up.delete("longttl.example.com.", "A") # zone max TTL decreases
up.send()
master.ctl("zone-sign")

wait4key(t, master, zone, 2, old_key, 9, 14, "ZSK remove") # old ZSK removed

t.end()
