#!/usr/bin/env python3

'''Test concurrent access to control socket.'''

from dnstest.utils import *
from dnstest.test import Test
import random
import threading
import time

zone_backup_running = dict()

def check_shutdown(server):
    if not server.log_search("shutting down"):
        set_err("server %s not shut down" % server.name)

def random_sleep():
    time.sleep(random.choice([0, 0, 0, 0, 0, 0.1, 0.2, 1, 2, 3 ]))

def random_ctl(server, zone_name):
    cmd = random.choice(["status", "reload", "stats", "zone-check", "zone-status", "zone-reload",
                         "zone-refresh", "zone-retransfer", "zone-notify", "zone-flush",
                         "zone-sign", "zone-keys-load", "zone-ksk-submitted", "zone-freeze",
                         "zone-thaw", "zone-xfr-freeze", "zone-xfr-thaw", "zone-read", "zone-get",
                         "zone-stats", "conf-init", "conf-list", "conf-read", "conf-diff",
                         "conf-get"])
    if cmd[0:5] == "zone-" and random.choice([False, True, True]):
        cmd += " " + zone_name
    if random.choice([False, True]):
        cmd = "-b " + cmd
    try:
        server.ctl(cmd, availability=False)
    except:
        pass

def random_ctls(server, zone_name):
    for i in range(random.choice([1, 1, 2, 3])):
        random_ctl(server, zone_name)
        random_sleep()

def ctl_txn_generic(server, txn_start, txn_modify, txn_commit, txn_abort, abort_failed_start):
    try:
        server.ctl("zone-status", availability=False)
    except:
        pass
    try:
        server.ctl(txn_start, availability=False)
    except:
        try:
            if abort_failed_start:
                server.ctl(txn_abort, availability=False)
        except:
            pass
        return
    random_sleep()
    try:
        server.ctl(txn_modify, availability=False)
        random_sleep()
        server.ctl(txn_commit, availability=False)
    except:
        attempts = 9
        while attempts > 0:
            time.sleep(2)
            attempts -= 1
            try:
                server.ctl(txn_abort, availability=False)
                attempts = 0
            except:
                pass

def bck_purge_rest(server, zone_name):
    global zone_backup_running
    if random.choice([False, True]) and not True in zone_backup_running.values():
        zone_name = " "
    if zone_name in zone_backup_running and zone_backup_running[zone_name]:
        return
    if " " in zone_backup_running and zone_backup_running[" "]:
        return
    zone_backup_running[zone_name] = True

    bckdir = "%s/backup" % server.dir
    bckdir += str(int(time.time()))
    bckdir = " +backupdir " + bckdir
    cmd_bck = "-t 14 -b zone-backup " + zone_name + bckdir
    cmd_pur = "-b -f zone-purge " + ("--" if zone_name == " " else zone_name)
    cmd_res = "-b zone-restore " + zone_name + bckdir
    ctl_txn_generic(server, cmd_bck, cmd_pur, cmd_res, cmd_res, False)
    try:
        server.ctl("zone-refresh " + zone_name, availability=False)
    except:
        pass
    try:
        server.ctl("zone-reload " + zone_name, availability=False)
    except:
        pass
    for i in range(10):
        try:
            resp = server.dig(zone_name, "SOA")
            if resp.count("SOA") > 0:
                break
        except:
            pass
        time.sleep(1)
    zone_backup_running[zone_name] = False

def ctl_update(server, zone_name):
    ctl_txn_generic(server, "-b zone-begin " + zone_name,
                    "zone-set " + zone_name + " abc 3600 A 1.2.3." + str(random.randint(1, 254)),
                    "zone-commit " + zone_name, "zone-abort " + zone_name, True)

def conf_update(server, zone_name):
    ctl_txn_generic(server, "conf-begin",
                    "conf-set zone[" + zone_name + "].zonemd-generate " + random.choice(["none", "zonemd-sha384", "zonemd-sha512", "remove"]),
                    "conf-commit", "conf-abort", True)

def random_thing(server, zone_name):
    scn = random.choice([random_ctls, random_ctls, random_ctls, random_ctls, bck_purge_rest, ctl_update, conf_update])
    scn(server, zone_name)

def run_thr(fun, server, zone_name):
    threading.Thread(target=fun, args=[server, zone_name]).start()

t = Test()

master = t.server("knot")
slave = t.server("knot")
zones = t.zone_rnd(2, dnssec=False, records=40)
t.link(zones, master, slave)

for z in zones:
    master.dnssec(z).enable = True
    master.dnssec(z).nsec3 = True

for s in [ master, slave ]:
    s.bg_workers = 3
    s.udp_workers = 1
    s.tcp_workers = 1

t.start()
slave.zones_wait(zones)

for i in range(60):
    s = random.choice([master, slave])
    z = random.choice(zones)
    run_thr(random_thing, s, z.name)
    random_sleep()

for s in [ master, slave ]:
    for z in zones:
        try:
            s.ctl("zone-xfr-thaw " + z.name, availability=False)
            s.ctl("zone-thaw " + z.name, availability=False)
            s.ctl("zone-notify " + z.name, availability=False)
        except:
            pass

for s in [ master, slave ]:
    try:
        s.ctl("conf-abort", availability=False)
    except:
        pass
    for z in zones:
        try:
            s.ctl("zone-abort " + z.name, availability=False)
        except:
            pass


t.sleep(10)
master.zones_wait(zones) # check that server is still operable
slave.zones_wait(zones) # check that server is still operable

t.end()

time.sleep(4)
for s in [ master, slave ]:
    check_shutdown(s)
