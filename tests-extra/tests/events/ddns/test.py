#!/usr/bin/env python3

'''Test for DDNS events replanning'''

import random, threading, socket

from dnstest.utils import *
from dnstest.test import Test

FLOOD_COUNT = 128
RELOAD_FREQ = FLOOD_COUNT // 16
UPDATE_SIZE = 32

chars="qwertyuiopasdfghjklzxcvbnm123456789"

def randstr():
    return ''.join(random.choice(chars) for x in range(63))

# This is here to disable garbage collection
sockets = []

def send_upd(up):
    if up.server.addr == "127.0.0.1":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.sendto(up.upd.to_wire(), (up.server.addr, up.server.port))
    sockets.append(sock)

def flood(server, zone):
    rr = None
    updates = []
    for i in range(FLOOD_COUNT):
        update = server.update(zone)
        for j in range(UPDATE_SIZE):
            rr = [randstr() + "." + zone[0].name, 3600, "TXT", randstr()]
            update.add(*rr)
        updates.append(update)
    for up_index, up in enumerate(updates):
        send_upd(up)
        if up_index % RELOAD_FREQ == 0:
            server.reload()
    return rr
    
random.seed()

t = Test()

zone = t.zone_rnd(1, dnssec=False)
master = t.server("knot")
t.link(zone, master, ddns=True)

t.start()

master.zone_wait(zone)

#flood server with updates
last_rr = flood(master, zone)

#reload
master.reload()

#wait for update processing
t.sleep(10)

#dig for last change
resp = master.dig(last_rr[0], "TXT")
resp.check(rdata = last_rr[3])

t.stop()


