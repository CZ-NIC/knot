#!/usr/bin/env python3

'''Monitor affecting innocent DDNS updates by processing faulty updates in the same bulk'''

from dnstest.test import Test
from dnstest.utils import *
import zone_generate
import random
import threading
import time

RND_LABEL_ORD = 0

def send_update(up):
    try:
        up.try_send()
    except:
        pass

def send_up_bg(up):
    threading.Thread(target=send_update, args=[up]).start()
    time.sleep(0.2)

def rnd_label(): # including trailing dot
    global RND_LABEL_ORD
    RND_LABEL_ORD += 1
    return ("%04d_" % RND_LABEL_ORD) + str(zone_generate.main(["-n", "1"])).rstrip()[-32:]

def check_faulty_update(faulty_up, server, zone, expect_fail, expect_faulty):
    test_rr = rnd_label() + "." + zone.name
    test_rd = rnd_label()
    test_first = random.choice([False, True])

    faulty_rr = rnd_label() + "." + zone.name
    faulty_rd = rnd_label()

    test_up = server.update(zone)
    test_up.add(test_rr, 3600, "TXT", test_rd)
    faulty_up.add(faulty_rr, 3600, "TXT", faulty_rd)

    server.ctl("zone-freeze " + zone.name, wait=True)
    serial = server.zone_wait(zone) # instant

    if test_first:
        send_up_bg(test_up)
        send_up_bg(faulty_up)
    else:
        send_up_bg(faulty_up)
        send_up_bg(test_up)

    server.ctl("zone-thaw " + zone.name)

    if expect_fail:
        time.sleep(2)
        server.zone_wait(zone, serial, equal=True, greater=False)
        resp = server.dig(test_rr, "TXT")
        resp.check(rcode=None, nordata=test_rd)
    else:
        server.zone_wait(zone, serial)
        resp = server.dig(test_rr, "TXT")
        resp.check(rcode="NOERROR", rdata=test_rd)

    resp = server.dig(faulty_rr, "TXT")
    if expect_faulty:
        resp.check(rcode=None, nordata=faulty_rd)
    else:
        resp.check(rcode="NOERROR", rdata=faulty_rd)

t = Test()

master = t.server("knot")
zones = t.zone("example.com.")
t.link(zones, master)

zone = zones[0]

t.start()

serial = master.zones_wait(zones)

nonex_rem = master.update(zone)
nonex_rem.delete(rnd_label(), "AAAA")
check_faulty_update(nonex_rem, master, zone, False, False)

prereq_yxnonex = master.update(zone)
prereq_yxnonex.prereq_yx(rnd_label(), "AAAA")
check_faulty_update(prereq_yxnonex, master, zone, False, True)

prereq_nxex = master.update(zone)
prereq_nxex.prereq_nx(zone.name, "SOA")
check_faulty_update(prereq_nxex, master, zone, False, True)

beside_cname = master.update(zone)
cn = rnd_label() + "." + zone.name
beside_cname.add(cn, 3600, "CNAME", "example.org.")
beside_cname.add(cn, 3600, "A", "1.2.3.6")
check_faulty_update(beside_cname, master, zone, False, False)
resp = master.dig(cn, "A")
resp.check(rcode="NOERROR", nordata="1.2.3.6")
resp.check_count(1, "CNAME")

cname_beside = master.update(zone)
cn = rnd_label() + "." + zone.name
cname_beside.add(cn, 3600, "A", "1.2.3.7")
cname_beside.add(cn, 3600, "CNAME", "example.org.")
check_faulty_update(cname_beside, master, zone, False, False)
resp = master.dig(cn, "A")
resp.check(rcode="NOERROR", rdata="1.2.3.7")
resp.check_count(0, "CNAME")

below_dname = master.update(zone)
dn = rnd_label() + "." + zone.name
subdn = rnd_label() + "." + dn
below_dname.add(dn, 3600, "DNAME", "example.org.")
below_dname.add(subdn, 3600, "A", "1.2.3.8")
check_faulty_update(below_dname, master, zone, False, False)
resp = master.dig(subdn, "A")
resp.check(rcode="NOERROR", nordata="1.2.3.8")
resp.check_count(1, "DNAME")
resp.check_count(1, "CNAME")

dname_below = master.update(zone)
dn = rnd_label() + "." + zone.name
subdn = rnd_label() + "." + dn
dname_below.add(subdn, 3600, "A", "1.2.3.8")
dname_below.add(dn, 3600, "DNAME", "example.org.")
check_faulty_update(dname_below, master, zone, False, False)
resp = master.dig(subdn, "A")
resp.check(rcode="NOERROR", rdata="1.2.3.8")
resp.check_count(0, "DNAME")
resp.check_count(0, "CNAME")
resp = master.dig("otherlabel." + dn, "A")
resp.check(rcode="NXDOMAIN")
resp.check_count(0, "DNAME")
resp.check_count(0, "CNAME")

dname_cname = master.update(zone)
cn = rnd_label() + "." + zone.name
dname_cname.add(cn, 3600, "CNAME", "example.org.")
dname_cname.add(cn, 3600, "DNAME", "example.org.")
check_faulty_update(dname_cname, master, zone, False, False)
resp = master.dig(cn, "A")
resp.check(rcode="NOERROR")
resp.check_count(0, "DNAME")
resp.check_count(1, "CNAME")
resp = master.dig("below." + cn, "A")
resp.check(rcode="NXDOMAIN")
resp.check_count(0, "DNAME")
resp.check_count(0, "CNAME")

t.end()
