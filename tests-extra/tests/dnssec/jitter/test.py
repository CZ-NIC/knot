#!/usr/bin/env python3

"""
DNSSEC jitter.
"""

from dnstest.utils import *
from dnstest.test import Test
from collections import Counter

t = Test()

master = t.server("knot")
zones = t.zone_rnd(16, records=1, dnssec=False)
for z in zones:
    z.update_soa(serial=1, refresh=600, retry=100, expire=3600)
t.link(zones, master)

master.conf_srv().background_workers = 8
master.dnssec(zones).enable = True
master.dnssec(zones).zsk_lifetime = 40
master.dnssec(zones).propagation_delay = 3
master.dnssec(zones).rrsig_lifetime = 30
master.dnssec(zones).rrsig_refresh = 5
master.dnssec(zones).rrsig_pre_refresh = 1
master.dnssec(zones).dnssec_jitter = 12

def wait_for_any(server, zns, rrtype, callback, arg):
    for i in range(100):
        t.sleep(0.3)
        for z in zns:
            resp = server.dig(z.name, rrtype)
            if callback(resp, arg):
                return

def has_serial(response, serial):
    return response.soa_serial() == serial

def has_dnskeys(response, dnskeys):
    return response.count("DNSKEY") == dnskeys

def get_dnskeys(server, zns):
    x = dict()
    for z in zones:
        resp = server.dig(z.name, "DNSKEY")
        x[z.name] = resp.count("DNSKEY")
    return x

def check_jitter(dictval, zns, old_val, new_val, msg):
    threshold = len(zns) * 20 / 100
    counts = dict(Counter(dictval.values()))
    detail_log(str(counts))
    isset(counts[old_val] > threshold, "%s: some old" % msg)
    isset(counts[new_val] > threshold, "%s: some new" % msg)
    compare(counts[old_val] + counts[new_val], len(zns), "%s: no other values" % msg)

t.start()
master.zones_wait(zones)

wait_for_any(master, zones, "SOA", has_serial, 3)
t.sleep(6)
serials = master.zones_wait(zones)
check_jitter(serials, zones, 2, 3, "RRSIG refresh")

wait_for_any(master, zones, "DNSKEY", has_dnskeys, 3)
t.sleep(6)
dnskeys = get_dnskeys(master, zones)
check_jitter(dnskeys, zones, 2, 3, "ZSK lifetime")

t.end()
