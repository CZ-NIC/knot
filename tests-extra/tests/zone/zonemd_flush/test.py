#!/usr/bin/env python3

'''Flushing the zone after ZONEMD generation.'''

import random

from dnstest.test import Test
from dnstest.utils import *

t = Test()

def has_zonemd(server, zone, alg):
    zfn = server.zones[zone.name].zfile.path
    with open(zfn) as zf:
        for line in zf:
            rr = line.split()
            if rr[0].lower() == zone.name.lower() and rr[2] == "ZONEMD" and str(alg) == "255":
                return False
            if rr[0].lower() == zone.name.lower() and rr[2] == "ZONEMD" and rr[5] == alg:
                return True
    return (str(alg) == "255")

def check_zonemd(server, zone, alg):
    t.sleep(2)
    for z in zone:
        if not has_zonemd(server, z, alg):
            set_err("NO ZONEMD in %s" % z.name)

def del_zonemd1(server, zone):
   zf = server.zones[zone.name].zfile
   zf.update_soa()

   with open(zf.path, "r+") as f:
       lines = f.readlines()
       f.seek(0)
       for line in lines:
           if "ZONEMD" not in line:
               f.write(line)
       f.truncate()

def del_zonemd(server, zone):
    for z in zone:
        del_zonemd1(server, z)

# NOTE parameter "serials" is updated
def check_serial_incr(server, zones, serials, expect_incr, msg):
    new_serials = server.zones_wait(zones, serials)
    for z in zones:
        if new_serials[z.name] != serials[z.name] + expect_incr:
            err_str = "%s: zone %s serial incremented by %d" % (msg, z.name, new_serials[z.name] - serial[z.name]);
            detail_log(err_str)
            set_err(err_str)
        serials[z.name] = new_serials[z.name]

master = t.server("knot")
slave = t.server("knot")

zone = t.zone_rnd(2, dnssec=False, records=10)
t.link(zone, master, slave, ixfr=random.choice([True, False]))

master.zonefile_sync = 0
master.zonemd_generate = "zonemd-sha384"
slave.zonemd_verify = True

t.start()

serial = slave.zones_wait(zone)
check_zonemd(master, zone, "1")

master.zonemd_generate = "zonemd-sha512"
master.gen_confile()
master.reload()
check_serial_incr(slave, zone, serial, 1, "alg change")
check_zonemd(master, zone, "2")

del_zonemd(master, zone)
master.ctl("zone-reload")
check_serial_incr(slave, zone, serial, 2, "ZONEMD removed")
check_zonemd(master, zone, "2")

for z in zone:
    master.random_ddns(z, allow_empty=False)
check_serial_incr(slave, zone, serial, 1, "DDNS")

for z in zone:
    # BUMP SOA serial by 3 thru DDNS
    resp = master.dig(z.name, "SOA")
    soa = resp.resp.answer[0].to_rdataset()[0].to_text()
    fields = soa.split()
    fields[2] = str(int(fields[2]) + 3)
    up = master.update(z)
    up.add(z.name, 3600, "SOA", ' '.join(fields))
    up.send("NOERROR")
check_serial_incr(slave, zone, serial, 3, "SOA DDNS")

for z in zone:
    master.zones[z.name].zfile.update_rnd()
master.ctl("zone-reload")
check_serial_incr(slave, zone, serial, 2, "ZF reload")
check_zonemd(master, zone, "2")

slave.zonemd_verify = False
slave.gen_confile()
slave.reload()

master.zonemd_generate = "none"
master.gen_confile()
master.reload()
check_zonemd(master, zone, "2")

master.zonemd_generate = "remove"
master.gen_confile()
master.reload()
check_serial_incr(slave, zone, serial, 1, "ZONEMD remove")
check_zonemd(master, zone, "255")

t.end()
