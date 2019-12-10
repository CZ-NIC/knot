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

def check_soa_diff(master, slave, zone, min_diff, max_diff):
    resp_m = master.dig(zone.name, "SOA", dnssec=True)
    resp_s = slave.dig(zone.name, "SOA", dnssec=True)
    resp_m.check_count(0, "RRSIG")
    resp_s.check_count(1, "RRSIG")
    real_diff = resp_s.soa_serial() - resp_m.soa_serial()

    if min_diff is not None and real_diff < min_diff:
        set_err("SOA serial difference min")
        detail_log("Low difference of SOA serials: master %d slave %d min diff %d" %
                   (resp_m.soa_serial(), resp_s.soa_serial(), min_diff))

    if max_diff is not None and real_diff > max_diff:
        set_err("SOA serial difference max")
        detail_log("High difference of SOA serials: master %d slave %d max diff %d" %
                   (resp_m.soa_serial(), resp_s.soa_serial(), max_diff))

def server_purge(server, zones, purge_kaspdb=True):
    shutil.rmtree(os.path.join(server.dir, "journal"), ignore_errors=True)
    shutil.rmtree(os.path.join(server.dir, "timers"), ignore_errors=True)
    if purge_kaspdb:
        shutil.rmtree(os.path.join(server.dir, "keys"), ignore_errors=True)
    for z in zones:
        os.remove(server.zones[z.name].zfile.path)

def test_one(master, slave, zone, master_policy, slave_policy, initial_serial,
             min_diff1, max_diff1, min_diff, max_diff):

    # configure serial policies and cleanup slave completely
    slave.zone_wait(zone)
    master.stop()
    slave.stop()
    server_purge(slave, zone)
    master.zones[zone[0].name].zfile.update_soa(serial=initial_serial)
    master.serial_policy = master_policy;
    slave.serial_policy = slave_policy;
    master.gen_confile()
    slave.gen_confile()
    master.start()
    slave.start()

    # initial test: after AXFR
    serial = slave.zone_wait(zone)
    check_soa_diff(master, slave, zone[0], min_diff1, max_diff1)

    # sign twice on slave to make difference
    slave.ctl("zone-sign example.com.")
    serial = slave.zone_wait(zone, serial)
    slave.ctl("zone-sign example.com.")
    serial = slave.zone_wait(zone, serial)
    check_soa_diff(master, slave, zone[0], min_diff, None)

    # test IXFR with shifted serial
    update = master.update(zone)
    update.add(new1, 3600, "A", addr)
    update.send("NOERROR")
    serial = slave.zone_wait(zone, serial)
    check_new_rr(slave, new1)
    check_soa_diff(master, slave, zone[0], min_diff, max_diff)

    # test AXFR bootstrap with shifted serial
    slave.stop()
    server_purge(slave, zone, False)
    update = master.update(zone)
    update.add("new2.example.com.", 3600, "A", addr)
    update.send("NOERROR")
    t.sleep(1)
    slave.start()
    slave.zone_wait(zone)
    check_new_rr(slave, new2)
    check_soa_diff(master, slave, zone[0], min_diff, max_diff)

t = Test()

master = t.server("knot")
slave  = t.server("knot")

zone = t.zone("example.com.", storage=".")

t.link(zone, master, slave, ddns=True)

slave.dnssec(zone).enable = True

t.start()

test_one(master, slave, zone, "increment", "increment", 1000, 0, 0, 2, 3)
test_one(master, slave, zone, "unixtime", "unixtime", int(time.time()), 1, 30, 1, 30)
test_one(master, slave, zone, "increment", "unixtime", int(time.time()), 1, 30, 5, None)
test_one(master, slave, zone, "unixtime", "increment", int(time.time()), 0, 0, None, -1)

rnd_master = random.choice(["dateserial", "increment"])
rnd_slave  = random.choice(["dateserial", "increment"])
test_one(master, slave, zone, rnd_master, rnd_slave, time.strftime("%Y%m%d01"), 0, 0, 2, 3)

if slave.log_search("fallback to AXFR"):
    set_err("fallback to AXFR")

t.end()
