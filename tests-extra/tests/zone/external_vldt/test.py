#!/usr/bin/env python3

"""
Test of external zone validation.
"""

from dnstest.libknot import libknot
from dnstest.utils import *
from dnstest.test import Test
import os
import random

t = Test()

master = t.server("knot")
slave = t.server("knot")
zone = t.zone("example.")
t.link(zone, master, slave)

ctl = libknot.control.KnotCtl()

def check_zf_types(fname, types):
    with open(fname, "r") as f:
        for t in types:
            line = f.readline()
            while line.startswith(";"):
                line = f.readline()
            compare(line.split()[2], t, "DIFF TYPE %s" % t)

def dump_file(server, purpose):
    return os.path.join(server.dir, purpose)

def log_count_expect(server, pattern, expct):
    fnd = server.log_search_count(pattern)
    if fnd != expct:
        detail_log("LOG SEARCH COUNT '%s' found %d expected %d" % (pattern, fnd, expct))
        set_err("LOG SEARCH COUNT %d != %d" % (fnd, expct))

ZONE = zone[0].name
LOG = "for external validation"

slave.async_start = True
slave.zones[ZONE].external = { "timeout": "10",
                               "new": dump_file(slave, "new"),
                               "rem": dump_file(slave, "diff"),
                               "add": dump_file(slave, "diff") }

def check_diff_types(types):
    check_zf_types(slave.zones[ZONE].external["add"], types)

master.notify_delay = 0
master.dnssec(zone[0]).enable = False

t.start()
serial = master.zone_wait(zone)

sockname = slave.ctl_sock_rnd(name_only=True)
ctl.connect(os.path.join(slave.dir, sockname))

t.sleep(2)
log_count_expect(slave, LOG, 1)
resp = slave.dig(ZONE, "SOA")
resp.check(rcode="SERVFAIL")
resp.check_count(0, "SOA")

ctl.send_block(cmd="zone-diff", zone=ZONE)
resp = ctl.receive_block()
isset("AAAA" in resp[ZONE]["ai."+ZONE], "ZONE-DIFF 1")
check_diff_types(["SOA", "NS", "NS", "MX", "NS"])
ctl.send_block(cmd="zone-commit", zone=ZONE)
resp = ctl.receive_block()
t.sleep(2)
resp = slave.dig(ZONE, "SOA")
resp.check_soa_serial(serial)

up = master.update(zone)
up.add("horse", 3600, "AAAA", "1::1")
up.add("tiger", 3600, "AAAA", "1::1")
up.send()
serial = master.zone_wait(zone, serial)

t.sleep(2)
log_count_expect(slave, LOG, 2)
ctl.send_block(cmd="zone-abort", zone=ZONE)
resp = ctl.receive_block()
t.sleep(2)
resp = slave.dig(ZONE, "SOA")
resp.check_soa_serial(serial - 1)
ctl.close()

up = master.update(zone)
up.add("snail", 3600, "AAAA", "1::1")
up.send()
serial = master.zone_wait(zone, serial)
t.sleep(2)
log_count_expect(slave, LOG, 3)
t.sleep(int(slave.zones[ZONE].external["timeout"]))
resp = slave.dig(ZONE, "SOA")
resp.check_soa_serial(serial - 2)

up = master.update(zone)
up.add("shark", 3600, "AAAA", "1::1")
up.send()
serial = master.zone_wait(zone, serial)

ctl.connect(os.path.join(slave.dir, sockname))
t.sleep(2)
log_count_expect(slave, LOG, 4)
ctl.send_block(cmd="zone-diff", zone=ZONE)
resp = ctl.receive_block()
isset("AAAA" in resp[ZONE]["horse."+ZONE], "ZONE-DIFF 2")
isset("AAAA" in resp[ZONE]["shark."+ZONE], "ZONE-DIFF 3")
isset("AAAA" in resp[ZONE]["snail."+ZONE], "ZONE-DIFF 3.5")
isset("AAAA" in resp[ZONE]["tiger."+ZONE], "ZONE-DIFF 4")
check_diff_types(["SOA", "SOA", "AAAA", "AAAA", "AAAA", "AAAA"])
ctl.send_block(cmd="zone-commit", zone=ZONE)
resp = ctl.receive_block()
t.sleep(2)
resp = slave.dig(ZONE, "SOA")
resp.check_soa_serial(serial)

ctl.send_block(cmd="zone-freeze", zone=ZONE)
resp = ctl.receive_block()
up.add("gibon", 3600, "AAAA", "1::1")
up.send()
serial = master.zone_wait(zone, serial)

slave.zonemd_generate = "zonemd-sha512"
slave.gen_confile()
t.sleep(2)
ctl.send_block(cmd="zone-thaw", zone=ZONE)
resp = ctl.receive_block()
t.sleep(0.3)
slave.reload()
try:
    ctl.send_block(cmd="zone-abort", zone=ZONE) # just in case the timing goes wrong and the reload does not abort the txn itself
    resp = ctl.receive_block()
except:
    pass

up = master.update(zone)
up.add("horse", 3600, "AAAA", "1::2")
up.delete("tiger", "AAAA", "1::1")
up.send()
serial = master.zone_wait(zone, serial)

t.sleep(4)
ctl.send_block(cmd="zone-diff", zone=ZONE)
resp = ctl.receive_block()
isset("AAAA" in resp[ZONE]["horse."+ZONE], "ZONE-DIFF 5")
isset("AAAA" in resp[ZONE]["gibon."+ZONE], "ZONE-DIFF 6")
isset("AAAA" in resp[ZONE]["tiger."+ZONE], "ZONE-DIFF 7")
check_diff_types(["SOA", "AAAA", "SOA", "ZONEMD", "AAAA", "AAAA"])
ctl.send_block(cmd="zone-commit", zone=ZONE)
resp = ctl.receive_block()
t.sleep(2)
resp = slave.dig(ZONE, "SOA")
resp.check_soa_serial(serial)

up = master.update(zone)
up.delete("horse", "AAAA", "1::1")
up.delete("shark", "AAAA", "1::1")
up.send()
serial = master.zone_wait(zone, serial)

t.sleep(2)
ctl.send_block(cmd="zone-diff", zone=ZONE)
resp = ctl.receive_block()
isset("AAAA" in resp[ZONE]["horse."+ZONE], "ZONE-DIFF 8")
isset("AAAA" in resp[ZONE]["shark."+ZONE], "ZONE-DIFF 9")
check_diff_types(["SOA", "ZONEMD", "AAAA", "AAAA", "SOA", "ZONEMD"])
slave.stop()
t.sleep(2)
log_count_expect(slave, "shutting down", 1)

t.end()
