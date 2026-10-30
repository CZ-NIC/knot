#!/usr/bin/env python3

"""
Restoring DNSSEC functionality upon losing private key(s).
"""

from dnstest.keys import Keymgr
from dnstest.test import Test
from dnstest.utils import *

import os

def privkey_dir(server):
    return os.path.join(server.keydir, "keys")

def privkey_del(server, keyid):
    os.remove(os.path.join(privkey_dir(server), "%s.pem" % keyid))

t = Test()

master = t.server("knot")
zones = t.zone("example.com.")
zone = zones[0]
t.link(zones, master)

master.dnssec(zones).enable = True
master.dnssec(zones).propagation_delay = 3
master.dnssec(zones).dnskey_ttl = 2
master.dnssec(zones).zone_max_ttl = 4

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

privkey_del(master, zsk)

up = master.update(zone)
up.add("fail", 0, "TXT", "no private ZSK")
up.send("SERVFAIL")

Keymgr.run_check(master.confile, zone.name, "set", ksk, "zsk=true")
Keymgr.run_check(master.confile, zone.name, "set", zsk, "pub-only=true")
master.ctl("zone-sign " + zone.name)
serial = master.zone_wait(zone, serial)

master.ctl("zone-flush", wait=True)
master.zone_verify(zone)

t.end()
