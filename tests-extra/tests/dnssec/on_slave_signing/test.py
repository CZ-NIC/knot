#!/usr/bin/env python3

'''Test for automatic DNSSEC signing on a slave Knot'''

from dnstest.utils import *
from dnstest.test import Test
import shutil
import random

new1 = "new1.example.com."
new2 = "new2.example.com."
addr = "192.0.0.42"

def check_new_rr(server, new_rr):
    resp = server.dig(new_rr, "A", dnssec=True)
    resp.check(rcode="NOERROR", rdata=addr)
    resp.check_count(1, "RRSIG")

def server_purge(server, zones, purge_kaspdb=True):
    shutil.rmtree(os.path.join(server.dir, "journal"), ignore_errors=True)
    if purge_kaspdb:
        shutil.rmtree(os.path.join(server.dir, "timers"), ignore_errors=True)
        shutil.rmtree(os.path.join(server.dir, "keys"), ignore_errors=True)
    for z in zones:
        os.remove(server.zones[z.name].zfile.path)

def test_one(master, slave, zone, master_policy, slave_policy, initial_serial):

    # configure serial policies and cleanup slave completely
    slave.zone_wait(zone)
    master.stop()
    slave.stop()
    server_purge(slave, zone)
    master.zones[zone[0].name].zfile.update_soa(serial=initial_serial)
    master.serial_policy = master_policy
    slave.serial_policy = slave_policy
    master.gen_confile()
    slave.gen_confile()
    master.start()
    slave.start()

    # initial test: after AXFR
    serial = slave.zone_wait(zone)
    if slave_policy == "incremental":
        slave.zone_wait(zone, initial_serial, equal=True, greater=False)

    # sign twice on slave to make difference
    slave.ctl("zone-sign example.com.")
    serial = slave.zone_wait(zone, serial)
    slave.ctl("zone-sign example.com.")
    serial = slave.zone_wait(zone, serial)

    # test IXFR with shifted serial
    update = master.update(zone)
    update.add(new1, 3600, "A", addr)
    update.send("NOERROR")
    serial = slave.zone_wait(zone, serial)
    check_new_rr(slave, new1)

    # test AXFR bootstrap with shifted serial
    slave.stop()
    server_purge(slave, zone, False)
    update = master.update(zone)
    update.add("new2.example.com.", 3600, "A", addr)
    update.send("NOERROR")
    t.sleep(1)
    slave.start()
    serial = slave.zone_wait(zone, serial)
    check_new_rr(slave, new2)

t = Test()

master = t.server("knot")
slave  = t.server("knot")

zone = t.zone("example.com.")

t.link(zone, master, slave, ddns=True)

slave.dnssec(zone).enable = True

t.start()

test_one(master, slave, zone, "increment",  "increment",  1000)
test_one(master, slave, zone, "unixtime",   "unixtime",   int(time.time()))
test_one(master, slave, zone, "increment",  "unixtime",   1000)
test_one(master, slave, zone, "unixtime",   "increment",  int(time.time()))
test_one(master, slave, zone, "dateserial", "unixtime",   2025010100)
test_one(master, slave, zone, "unixtime",   "dateserial", int(time.time()))

if slave.log_search("fallback to AXFR"):
    set_err("fallback to AXFR")

t.end()
