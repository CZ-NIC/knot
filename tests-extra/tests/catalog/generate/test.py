#!/usr/bin/env python3

'''Test of Catalog zone generation.'''

from dnstest.test import Test
from dnstest.utils import compare, set_err, detail_log
from dnstest.libknot import libknot
import os
import random
import shutil
import time

USE_CTL = random.choice([True, False, False])

t = Test()

def wait_for_zonefile(server, zonename, max_age, timeout):
    fn = os.path.join(server.dir, "catalog", zonename + "zone")
    while timeout > 0:
        if os.path.exists(fn):
            age = time.time() - os.path.getmtime(fn)
        else:
            age = max_age + 1
        if age <= max_age:
            break
        timeout -= 1
        t.sleep(1)
    t.sleep(max_age)

master = t.server("knot")
slave = t.server("knot")

catz = t.zone("example.")
zone = t.zone("example.com.")

t.link(catz, master, slave)
t.link(zone, master, slave)

master.cat_generate(catz)
slave.cat_interpret(catz)
master.cat_member(zone, catz)
slave.cat_hidden(zone)

slave.dnssec(catz[0]).enable = True
slave.dnssec(catz[0]).single_type_signing = True

def ctl_begin():
    ctl = libknot.control.KnotCtl()
    ctl.connect(os.path.join(master.dir, "knot.sock"))
    ctl.send_block(cmd="conf-begin")
    resp = ctl.receive_block()
    return ctl

def ctl_end(ctl):
    ctl.send_block(cmd="conf-commit")
    resp = ctl.receive_block()
    ctl.send(libknot.control.KnotCtlType.END)
    ctl.close()

def ctl_add_zone(ctl, zone_name):
    ctl.send_block(cmd="conf-set", section="zone", item="domain", data=zone_name)
    resp = ctl.receive_block()
    ctl.send_block(cmd="conf-set", section="zone", item="template", identifier=zone_name, data="catalog-default")
    resp = ctl.receive_block()
    ctl.send_block(cmd="conf-set", section="zone", item="catalog-zone", identifier=zone_name, data=catz[0].name)
    resp = ctl.receive_block()
    ctl.send_block(cmd="conf-set", section="zone", item="catalog-role", identifier=zone_name, data="member")
    resp = ctl.receive_block()
    ctl.send_block(cmd="conf-set", section="zone", item="file", identifier=zone_name, data=os.path.join(master.dir, "generic.zone"))
    resp = ctl.receive_block()

t.start()

# testcase 1: initial catalog zone with 1 member
slave.zones_wait(zone)

# testcase 2: adding member zones dynamically/online/offline
zone_add = t.zone("flags.") + t.zone("records.")
if USE_CTL:
    shutil.copy(t.data_dir + "generic.zone", os.path.join(master.dir, "generic.zone"))
    ctl = ctl_begin()
    ctl_add_zone(ctl, "flags.")
    ctl_add_zone(ctl, "records.")
    ctl_end(ctl)
else:
    t.link(zone_add, master, slave)
    for z in zone_add:
        master.cat_member(z, catz)
        slave.cat_hidden(z)

    master.gen_confile()

    add_online = random.choice([True, False])
    if add_online:
        master.reload()
    else:
        master.stop()
        t.sleep(1)
        master.start()

slave.zones_wait(zone + zone_add)

# testcase 3: removing member zone dynamically/online/offline
serial_bef_rem = slave.zone_wait(catz, tsig=True)
master.ctl("-f zone-purge example.com")
if USE_CTL:
    ctl = ctl_begin()
    ctl.send_block(cmd="conf-unset", section="zone", item="domain", data="example.com.")
    resp = ctl.receive_block()
    ctl_end(ctl)
else:
    master.zones.pop("example.com.")
    master.gen_confile()

    add_online = random.choice([True, False])
    if add_online:
        master.reload()
    else:
        master.stop()
        t.sleep(1)
        master.start()

slave.zone_wait(catz, serial_bef_rem, tsig=True)
t.sleep(2) # allow the member zone to actually be purged
resp = slave.dig("example.com.", "SOA")
resp.check(rcode="REFUSED")

#testcase 4: remove/add same member zone while slave offline, with purge
resp0 = slave.dig("records.", "DNSKEY")
resp0.check_count(1, "DNSKEY")
dnskey0 = resp0.resp.answer[0].to_rdataset()
slave.stop()

if USE_CTL:
    ctl = ctl_begin()
    ctl.send_block(cmd="conf-unset", section="zone", item="domain", data="records.")
    resp = ctl.receive_block()
    ctl_end(ctl)
    t.sleep(7)
    master.ctl("-f zone-purge +orphan records.")
    ctl = ctl_begin()
    ctl_add_zone(ctl, "records.")
    ctl_end(ctl)
else:
    temp_rem = master.zones.pop("records.")
    master.gen_confile()
    master.reload()
    t.sleep(7)
    master.ctl("-f zone-purge +orphan records.")
    master.zones["records."] = temp_rem
    master.gen_confile()
    master.reload()

slave.start()
wait_for_zonefile(slave, "records.", 3, 30)
slave.ctl("zone-refresh")
wait_for_zonefile(slave, "records.", 3, 30)
resp1 = slave.dig("records.", "DNSKEY")
resp1.check_count(1, "DNSKEY")
dnskey1 = resp1.resp.answer[0].to_rdataset()
if dnskey0 == dnskey1:
    set_err("ZONE NOT PURGED")

#testcase 5: reload and don't reload a zone depending on the config change
if USE_CTL:
    shutil.copy(t.data_dir + "generic.upd", os.path.join(master.dir, "generic.zone"))

    ctl = ctl_begin()
    ctl.send_block(cmd="conf-set", section="zone", identifier="flags.", item="zone-max-size", data="10000")
    resp = ctl.receive_block()
    ctl.send_block(cmd="conf-set", section="zone", identifier="records.", item="comment", data="don't reload")
    resp = ctl.receive_block()
    ctl_end(ctl)

    t.sleep(2)
    resp = master.dig("flags.", "SOA")
    compare(resp.soa_serial(), 10, "master zone reloaded")
    resp = master.dig("records.", "SOA")
    compare(resp.soa_serial(), 1, "master zone not reloaded")
    slave.zone_wait(zone_add[0], 1)

t.end()
