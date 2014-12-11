#!/usr/bin/env python3

'''Stress test for multiple incoming DDNS and outgoing IXFRs'''

import random, socket, os

from dnstest.utils import *
from dnstest.test import Test

FLOOD_COUNT = 4096
UPDATE_SIZE = 16

chars="qwertyuiopasdfghjklzxcvbnm123456789"

def randstr():
    return ''.join(random.choice(chars) for _ in range(63))

def send_upd(up):
    family = socket.AF_INET if up.server.addr == "127.0.0.1" else socket.AF_INET6
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.sendto(up.upd.to_wire(), (up.server.addr, up.server.port))

def flood(server, zone):
    rr = None
    updates = []
    for i in range(FLOOD_COUNT):
        update = server.update(zone)
        for j in range(UPDATE_SIZE):
            rr = [randstr() + "." + zone[0].name, 3600, "TXT", randstr()]
            update.add(*rr)
        updates.append(update)
    for up in updates:
        send_upd(up)
    return rr

random.seed()

t = Test()

zone = t.zone_rnd(1, dnssec=False)
master = t.server("knot")
master.ixfr_fslimit = "1000k"

slaves = [t.server("knot") for _ in range(2)]
for s in slaves:
    t.link(zone, master, s, ddns=True, ixfr=True)

t.start()

for s in slaves + [master]:
    s.zone_wait(zone)

# flood server with updates
last_rr = flood(master, zone)

# wait for update and ixfr processing
t.sleep(10)

# restart servers and dig for last change
for s in slaves + [master]:
    s.stop()
    s.start()
    s.zone_wait(zone)
    resp = s.dig(last_rr[0], "TXT")
    resp.check(rdata = last_rr[3])

# get journal size
st = os.stat(master.dir + "/" + zone[0].name.lower() + "diff.db")
if st.st_size > 2000 * 1024:
    detail_log("Journal too big, should be 1000k, is: " + str(st.st_size // 1024) + "k")
    set_err("JOURNAL SIZE OVERFLOW")

t.stop()

