#!/usr/bin/env python3

"""
Restoring DNSSEC functionality upon losing private key(s).
"""

from dnstest.keys import Keymgr
from dnstest.test import Test
from dnstest.utils import *

import os
import re
import time

import dns.dnssec

PARENT_DS_KEYTAG="0"

def privkey_dir(server):
    return os.path.join(server.keydir, "keys")

def privkey_del(server, keyid):
    os.remove(os.path.join(privkey_dir(server), "%s.pem" % keyid))

def listline2keytag(line):
    return re.search(r"\btag=(\d+)", line).group(1)

def reconf_manual(server, z, man):
    server.dnssec(z).manual = man
    server.gen_confile()
    server.reload()

def wait_for(server, name, rrt, count, deadline):
    for i in range(deadline):
        resp = server.dig(name, rrt)
        if len(resp.resp.answer[0].to_rdataset()) == count:
            return
        time.sleep(1)

def check_dnssec(server, z):
    server.ctl("zone-flush " + z.name, wait=True)
    server.zone_verify(z)

    resp = server.dig(z.name, "DNSKEY", dnssec=True)
    dnskeys = resp.resp.answer[0].to_rdataset()
    rrsigs = resp.resp.answer[1].to_rdataset()
    d_have_keytag = False
    r_have_keytag = False

    for d in dnskeys:
        if dns.dnssec.key_id(d) == int(PARENT_DS_KEYTAG):
            d_have_keytag = True
    for r in rrsigs:
        rsplit = str(r).split()
        if rsplit[0] == "DNSKEY" and int(rsplit[6]) == int(PARENT_DS_KEYTAG):
            r_have_keytag = True
    isset(d_have_keytag, "DNSKEY corresponds DS %s" % PARENT_DS_KEYTAG)
    isset(r_have_keytag, "RRSIG corresponds DS %s" % PARENT_DS_KEYTAG)

t = Test()

master = t.server("knot")
zones = t.zone("example.com.")
zone = zones[0]
t.link(zones, master)

master.dnssec(zones).enable = True
master.dnssec(zones).propagation_delay = 3
master.dnssec(zones).dnskey_ttl = 2
master.dnssec(zones).zone_max_ttl = 4
master.conf_ss("submission", zones).timeout = 5

t.start()
serial = master.zone_wait(zone)

_, keys, _ = Keymgr.run_check(master.confile, zone.name, "list")
keys = keys.splitlines()
compare(len(keys), 2, "Init: two keys")

for k in keys:
    if "zsk=yes" in k:
        zsk = k.split()[0]
    elif "ksk=yes" in k:
        ksk = k.split()[0]
        PARENT_DS_KEYTAG = listline2keytag(k)

privkey_del(master, zsk)

up = master.update(zone)
up.add("fail", 0, "TXT", "no private ZSK")
up.send("SERVFAIL")

Keymgr.run_check(master.confile, zone.name, "set", ksk, "zsk=true")
Keymgr.run_check(master.confile, zone.name, "set", zsk, "pub-only=true")
master.ctl("zone-sign " + zone.name)
master.zone_wait(zone, serial)

check_dnssec(master, zone)

_, keys, _ = Keymgr.run_check(master.confile, zone.name, "list")
for k in keys.splitlines():
    if "ksk=yes" in k and not "zsk=yes" in k:
        ksk = k.split()[0]
        PARENT_DS_KEYTAG = listline2keytag(k)

Keymgr.run_check(master.confile, zone.name, "delete", zsk)
wait_for(master, zone.name, "DNSKEY", 2, 20)
check_dnssec(master, zone)

privkey_del(master, ksk)
serial = master.zone_wait(zone)

up = master.update(zone)
up.add("fail", 0, "TXT", "no private KSK")
up.send("SERVFAIL")

Keymgr.run_check(master.confile, zone.name, "set", ksk, "pub-only=true")
_, newksk, _ = Keymgr.run_check(master.confile, zone.name, "generate", "ksk=true", "zsk=false", "publish=+5s", "active=+5s")
newksk = newksk.split()[0]
reconf_manual(master, zone, True)

_, keys, _ = Keymgr.run_check(master.confile, zone.name, "list")
for k in keys.splitlines():
    if k.split()[0] == newksk:
        PARENT_DS_KEYTAG = listline2keytag(k)

master.zone_wait(zone, serial)
check_dnssec(master, zone)

Keymgr.run_check(master.confile, zone.name, "delete", ksk)
reconf_manual(master, zone, False)
wait_for(master, zone.name, "DNSKEY", 2, 20)
check_dnssec(master, zone)

t.end()
