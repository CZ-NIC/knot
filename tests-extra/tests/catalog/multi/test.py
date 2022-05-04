#!/usr/bin/env python3

'''Test of multiple Catalog zones.'''

from dnstest.test import Test
from dnstest.utils import set_err, detail_log
import dnstest.params

import glob
import shutil
from subprocess import DEVNULL, PIPE, Popen
import subprocess
import random
import dns

t = Test()

def cat_zf(server, zone):
    return server.zones[zone.name].zfile.path

def upd_cat_zf(server, zone, member):
    uniq = str(random.randint(1000000, 9999999))
    ptr = "%s.zones.%s 0 PTR %s" % (uniq, zone.name, member)
    with open(cat_zf(server, zone), "a") as zf:
        zf.write(ptr + "\n")

def check_exists(server, member, expect_exists, msg):
    resp = server.dig(member, "SOA")
    rc = dns.rcode.to_text(resp.resp.rcode())
    if rc == "SERVFAIL":
        if not expect_exists:
            set_err("%s: exists %s" % (msg, member))
    elif rc == "REFUSED":
        if expect_exists:
            set_err("%s: not exists %s" % (msg, member))
    else:
        set_err("Unexpected rcode %s" % rc)

master = t.server("knot")

# Zone setup
zone = t.zone("example.com.") + t.zone("catalog1.", storage=".") + t.zone("catalog2.", storage=".") + t.zone("catalog3.", storage=".")

t.link(zone, master)

master.cat_interpret(zone[1])
master.cat_interpret(zone[2])
master.cat_interpret(zone[3])

t.start()
t.sleep(5)

upd_cat_zf(master, zone[1], "member1.example.")
upd_cat_zf(master, zone[2], "member2.example.")
upd_cat_zf(master, zone[3], "member3.example.")

master.ctl("zone-reload %s" % zone[1].name)
t.sleep(5)

check_exists(master, "member1.example.", True, "First")
check_exists(master, "member2.example.", True, "First")
check_exists(master, "member3.example.", True, "First")

master.ctl("zone-reload %s" % zone[2].name)
t.sleep(5)

check_exists(master, "member1.example.", True, "Second")
check_exists(master, "member2.example.", True, "Second")
check_exists(master, "member3.example.", True, "Second")

t.end()
