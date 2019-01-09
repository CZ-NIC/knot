#!/usr/bin/env python3

'''Test Knot stability if many zones are added, modified and removed, like by dns_sql2zf.py'''

from dnstest.test import Test
from dnstest.utils import set_err
import random

conf_txn_open = False

def knotc_send(type, server, zone):
    global conf_txn_open
    if type == 0:
        try:
            server.ctl("zone-reload %s" % zone.name)
        except:
            if conf_txn_open:
                knotc_send_end(server)
                knotc_send(0, server, zone)
            else:
                knotc_send(2, server, zone)
    else:
        try:
            if not conf_txn_open:
                server.ctl("conf-begin")
                conf_txn_open = True
            if type > 0:
                try:
                    server.ctl("conf-set zone[%s]" % zone.name)
                    server.ctl("conf-set zone[%s].file %s" % (zone.name, zone.zfile.path))
                except:
                    if type > 1:
                        raise
                    else:
                        knotc_send_end(server)
                        knotc_send(0, server, zone)
            else:
                server.ctl("conf-unset zone[%s]" % zone.name)
        except:
            server.ctl("conf-abort")
            conf_txn_open = False
            raise

def set_policy(server):
    server.ctl("conf-begin")
    server.ctl("conf-set template[default].dnssec-signing on")
    server.ctl("conf-set template[default].dnssec-policy example.com.")
    server.ctl("conf-set template[default].journal-content all")
    server.ctl("conf-set template[default].zonefile-load difference")
    server.ctl("conf-commit")

def knotc_send_end(server):
    global conf_txn_open
    if conf_txn_open:
        server.ctl("conf-commit")
        conf_txn_open = False

def rnd_zone(server):
    if server.zones:
        name = random.choice(list(server.zones.keys()))
        return server.zones[name]
    else:
        return None

def add_zone(test, server):
    new_zone = test.zone_rnd(1, dnssec=False, records=10)
    test.link(new_zone, server, ixfr=True, journal_content="all")
    knotc_send(1, server, server.zones[new_zone[0].name])

def mod_zone(test, server):
    z = rnd_zone(server)
    if z:
        z.zfile.update_rnd()
        z.zfile.update_soa(z.zfile.get_soa_serial() + 100)
        knotc_send(0, server, z)

def rem_zone(test, server):
    z = rnd_zone(server)
    if z:
        knotc_send(-1, server, z)
        try:
            server.ctl("-f zone-purge %s" % z.name)
        except:
            pass
        del server.zones[z.name]

def rnd_change(test, server):
    funcs = [
        add_zone, add_zone, add_zone, add_zone, add_zone,
        mod_zone, mod_zone, mod_zone, mod_zone, mod_zone, mod_zone, mod_zone, mod_zone,
        rem_zone, rem_zone, rem_zone
    ];
    func = random.choice(funcs)
    func(test, server)

def rnd_changes(test, server, count):
    for i in range(0, count):
        rnd_change(test, server)
    knotc_send_end(server)
    test.sleep(5)

def chk_serials(server):
    for zn in server.zones:
        z = server.zones[zn]
        zf_serial = z.zfile.get_soa_serial()
        kn_serial = server.dig_serial(zn)
        if (kn_serial - zf_serial) not in [0, 1]:
            set_err("[%s] real serial (%d) lower than zf serial (%d)" % (zn, kn_serial, zf_serial))
            server.ctl("zone-status %s" % zn)

t = Test()
s = t.server("knot")
s.valgrind = []
s.journal_db_size = 200 * 1024 * 1024
zone_init = t.zone("example.com.") + t.zone_rnd(5, dnssec=False, records=50)
t.link(zone_init, s, ixfr=True, journal_content="all")
for z in zone_init:
    s.dnssec(z).enable = True
s.zonefile_sync = -1
t.start()
s.zones_wait(zone_init)

set_policy(s)
t.sleep(2)
s.zones_wait(zone_init)

for i in range(1, 25):
    for j in range(1, 10):
        rnd_changes(t, s, 7)
    chk_serials(s)

t.end()

