#!/usr/bin/env python3

'''Stress test for multiple incoming DDNS and outgoing IXFRs'''

import random, socket, os

from dnstest.utils import *
from dnstest.test import Test

UPDATE_COUNT = 40
UPDATE_SIZE = 450

chars="qwertyuiopasdfghjklzxcvbnm123456789"

def randstr():
    return ''.join(random.choice(chars) for _ in range(63))

def flood(server, zone):
    rr = None
    updates = []
    for i in range(UPDATE_COUNT):
        update = server.update(zone)
        for j in range(UPDATE_SIZE):
            rr = [randstr() + "." + zone[0].name, 3600, "TXT", randstr()]
            update.add(*rr)
        update.send()
    return rr

random.seed()

t = Test()

zone = t.zone_rnd(1, dnssec=False, records=4)
master = t.server("knot")

# set journal limit for the master
master.ixfr_fslimit = "800k"

slaves = [t.server("knot") for _ in range(2)]
# set journal limit for one of the slaves
slaves[0].ixfr_fslimit = "500k"

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

# check journal sizes
st = os.stat(master.dir + "/" + zone[0].name.lower() + "diff.db")
if st.st_size > 1050 * 1024:
    detail_log("Journal too big, should be max 800k, is: " + str(st.st_size // 1024) + "k")
    set_err("JOURNAL SIZE OVERFLOW")

st = os.stat(slaves[0].dir + "/" + zone[0].name.lower() + "diff.db")
if st.st_size > 650 * 1024:
    detail_log("Journal too big, should be max 500k, is: " + str(st.st_size // 1024) + "k")
    set_err("JOURNAL SIZE OVERFLOW")

t.stop()

