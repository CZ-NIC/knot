#!/usr/bin/env python3

'''Test for automatic DNSSEC signing on a slave Knot'''

from dnstest.utils import *
from dnstest.test import Test
import shutil

serial = 2010111213
addr = "192.0.0.42"

def check_soa_diff(master, slave, zone, expect_diff):
    resp_m = master.dig(zone.name, "SOA", dnssec=True)
    resp_s = slave.dig(zone.name, "SOA", dnssec=True)
    resp_m.check_count(0, "RRSIG")
    resp_s.check_count(1, "RRSIG")

    real_diff = resp_s.soa_serial() - resp_m.soa_serial()
    if real_diff != expect_diff:
        set_err("SOA serial difference")
        detail_log("Unexpected difference of SOA serials: master %d slave %d expected diff %d" %
                   (resp_m.soa_serial(), resp_s.soa_serial(), expect_diff))

def server_purge(server, zones):
    shutil.rmtree(os.path.join(server.dir, "journal"))
    shutil.rmtree(os.path.join(server.dir, "timers"))
    for z in zones:
        os.remove(server.zones[z.name].zfile.path)

t = Test()

master = t.server("knot")
slave  = t.server("knot")

zone = t.zone("example.com.", storage=".")

t.link(zone, master, slave, ddns=True)

slave.dnssec(zone).enable = True

t.start()

# initial test: after AXFR
slave.zone_wait(zone)
check_soa_diff(master, slave, zone[0], 0)

# sign twice on slave to make difference
slave.ctl("zone-sign example.com.")
t.sleep(1)
slave.ctl("zone-sign example.com.")
t.sleep(3)
check_soa_diff(master, slave, zone[0], 2)

# test IXFR with shifted serial
update = master.update(zone)
update.add("new.example.com.", 3600, "A", addr)
update.send("NOERROR")
t.sleep(2)
check_soa_diff(master, slave, zone[0], 2)

# test AXFR bootstrap with shifted serial
slave.stop()
server_purge(slave, zone)
update = master.update(zone)
update.add("new2.example.com.", 3600, "A", addr)
update.send("NOERROR")
slave.start()
slave.zone_wait(zone)
check_soa_diff(master, slave, zone[0], 2)

t.end()
