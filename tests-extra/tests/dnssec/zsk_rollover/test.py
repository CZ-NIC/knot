#!/usr/bin/env python3

"""
Check of automatic ZSK rollover with changing zone TTLs.
"""

from dnstest.utils import *
from dnstest.test import Test

def get_salt(server, zone):
    resp = server.dig(zone[0].name, "NSEC3PARAM")
    return resp.resp.answer[0].to_rdataset()[0].to_text().split()[-1]

last_salt = ""

def check_salt(server, zone, shall_differ):
    global last_salt
    salt = get_salt(server, zone)
    if shall_differ != (salt != last_salt):
        msg_not = " " if shall_differ else " not "
        detail_log("Salt %s, Last salt %s, shall%sdiffer" % (salt, last_salt, msg_not))
        set_err("NSEC3 salt shall%sdiffer" % msg_not)
    last_salt = salt

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
master.dnssec(zone).nsec3 = True
master.dnssec(zone).nsec3_salt_lifetime = -1

t.start()
master.zone_wait(zone)
check_salt(master, zone, True)

wait4key(t, master, zone, 3, -1, 6, 20, "ZSK publish") # new ZSK published
old_key = zsk_keytag(master, zone)
check_salt(master, zone, False)

wait4key(t, master, zone, 3, old_key, 4, 8, "ZSK switch") # active ZSK switched
check_salt(master, zone, True)
up = master.update(zone)
up.delete("longttl.example.com.", "A") # zone max TTL decreases
up.send()
master.ctl("zone-sign")

wait4key(t, master, zone, 2, old_key, 9, 14, "ZSK remove") # old ZSK removed
check_salt(master, zone, False)

t.end()
