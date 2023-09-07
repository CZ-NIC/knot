#!/usr/bin/env python3

'''Test of adjusting additionals'''

from dnstest.test import Test
import random
import string

RECORDS_INIT = 100
RECORDS_ADD = 30
RECORDS_REM = 20
RECORDS_DIG = 60
LABELS_MAX = 3
RRTYPES = ["A", "AAAA", "NS", "MX", "SVCB"]
STEPS = 20

def rnd_name(zonename):
    n_labels = random.randint(1, LABELS_MAX)
    labels = [ random.choice(string.ascii_lowercase + "**") for i in range(n_labels) ]
    return ".".join(labels) + "." + zonename

def rnd_add(zonename, update):
    typ = random.choice(RRTYPES)
    rdata = rnd_name(zonename)
    if typ == "A":
        rdata = "1.2.3.4"
    elif typ == "AAAA":
        rdata = "1::2"
    elif typ != "NS":
        rdata = "0 " + rdata
    update.add(rnd_name(zonename), 3600, typ, rdata)

def rnd_adds(zonename, update, count):
    for i in range(count):
        rnd_add(zonename, update)

def rnd_dnames(zonename, server, count):
    dnames = []
    with open(server.zones[zonename].zfile.path, 'r') as zonefile:
        for fline in zonefile:
            line = fline.split(None, 4)
            if len(line) < 3 or line[0][0] in [";", "@"] or line[2] not in RRTYPES or line[0] == zonename:
                continue
            dnames.append((line[0], line[2]))
    return random.sample(dnames, count) if count < len(dnames) else dnames

def rnd_dels(zonename, server, update, count):
    for (rec, typ) in rnd_dnames(zonename, server, count):
        update.delete(rec, typ)

def rnd_digs(zonename, server, count):
    for (name, typ) in rnd_dnames(zonename, server, count):
        resp = server.dig(name, typ, dnssec=False, timeout=1800)
        resp.check(rcode="NOERROR")

t = Test(stress=False)

master = t.server("knot")
zones = t.zone("example.")
t.link(zones, master, journal_content="all")

t.start()

serial = master.zones_wait(zones)
for z in zones:
    up = master.update(z)
    rnd_adds(z.name, up, RECORDS_INIT)
    up.send("NOERROR")

for i in range(STEPS):
    master.flush(wait=True)
    t.sleep(1)

    for z in zones:
        rnd_digs(z.name, master, RECORDS_DIG)

        up = master.update(z)
        rnd_dels(z.name, master, up, RECORDS_REM)
        rnd_adds(z.name, up, RECORDS_ADD)
        up.send("NOERROR")

master.flush(wait=True)
t.sleep(1)
for z in zones:
    rnd_digs(z.name, master, 1000000000)

t.end()
