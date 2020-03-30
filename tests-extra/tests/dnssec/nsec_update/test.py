#!/usr/bin/env python3

'''Test for NSEC and NSEC3 fix after zone update (ddns, ixfr)'''

from dnstest.utils import *
from dnstest.test import Test
from dnstest.keys import Keymgr
import random

t = Test()

master0 = t.server("knot")
master = t.server("knot")
slave = t.server("knot")
zones1 = t.zone_rnd(20, dnssec=False, records=1) + \
         t.zone_rnd(20, dnssec=False, records=10) + \
         t.zone_rnd(5, dnssec=False, records=100) + \
         t.zone("records.")
zone0 = t.zone("dk.", storage=".")
zones = zones1 + zone0

t.link(zone0, master0, master)
t.link(zones, master, slave)

master.disable_notify = True
slave.disable_notify = True

for zone in zones:
    master.dnssec(zone).enable = True
    master.dnssec(zone).nsec3 = random.choice([True, False])
    master.dnssec(zone).nsec3_iters = 2
    master.dnssec(zone).nsec3_salt_len = random.choice([0, 1, 9, 64, 128, 255])
    master.dnssec(zone).nsec3_opt_out = (random.random() < 0.5)

t.start()
master.zones_wait(zones)
slave.ctl("zone-refresh")
slave.zones_wait(zones)

# initial convenience check
t.xfr_diff(master, slave, zones)

# update master
master.flush()
t.sleep(2)
for zone in zones1:
    master.random_ddns(zone)

up = master0.update(zone0)
up.add("dk.", "86400", "SOA", "a.nic.dk. mail.dk. 1666666666 600 300 1814400 7200")
up.delete("nextlevelinlife.dk.", "NS")
up.delete("nextlevelinlife.dk.", "DS")
up.add("nextlevelinlife.dk.", "86400", "NS", "test.com.")
up.send("NOERROR")

t.sleep(1)
master.ctl("zone-refresh")

t.sleep(4) # zones_wait fails if an empty update is generated
after_update = master.zones_wait(zones)

# sync slave with current master's state
slave.ctl("zone-refresh")
slave.zones_wait(zones, after_update, equal=True, greater=False)

# flush so that we can do zone_verify
slave.flush()

# re-sign master and check that the re-sign made nothing
master.ctl("zone-sign")
after_update15 = master.zones_wait(zones, after_update, equal=False, greater=True)

t.xfr_diff(master, slave, zones, no_rrsig_rdata=True)
for zone in zones:
    slave.zone_verify(zone)

# sync slave with current master's state
slave.ctl("zone-refresh")
slave.zones_wait(zones, after_update15, equal=True, greater=False)

# update master by adding delegation with nontrivial NONAUTH nodes
for zone in zones:
    up = master.update(zone)
    if random.random() < 0.5:
        up.add("deleg390280", 3600, "NS", "a.ns.deleg390280")
        up.add("a.ns.deleg390280", 3600, "A", "1.2.54.30")
    else:
        up.add("deleg390281", 3600, "NS", "ns.deleg390280")
        up.add("ns.deleg390281", 3600, "A", "1.2.54.31")
    up.send("NOERROR")

# update master by making empty-non-terminal from non-empty-non-terminal
# above a delegation (create first)
for zone in zones:
    up = master.update(zone)
    up.add("ent", 3600, "A", "1.2.3.4")
    up.add("deleg.ent", 3600, "NS", "ns2.example.net.")
    up.send("NOERROR")
    t.sleep(1)
    up = master.update(zone)
    up.delete("ent", "A")
    up.send("NOERROR")

t.sleep(1)
master.ctl("zone-refresh")

after_update2 = master.zones_wait(zones, after_update15, equal=False, greater=True)

# sync slave with current master's state
slave.ctl("zone-refresh")
slave.zones_wait(zones, after_update2, equal=True, greater=False)

# flush so that we can do zone_verify
slave.flush()

# re-sign master and check that the re-sign made nothing
master.ctl("zone-sign")
after_update25 = master.zones_wait(zones, after_update2, equal=False, greater=True)

t.xfr_diff(master, slave, zones, no_rrsig_rdata=True)
for zone in zones:
    slave.zone_verify(zone)

if slave.log_search("no such record in zone found") or slave.log_search("fallback to AXFR"):
    set_err("IXFR ERROR")

# update salt with keymgr and see if zone correctly re-NSEC3-d after update
for z in zones1:
    salt = "-" if master.dnssec(z).nsec3_salt_len == 0 else "fe" * master.dnssec(z).nsec3_salt_len
    Keymgr.run_check(master.confile, z.name, "nsec3-salt", salt)
    up = master.update(z)
    up.add("abc." + z.name, 3600, "A", "1.2.3.4")
    up.send("NOERROR")

t.sleep(1)
slave.ctl("zone-refresh")
t.sleep(3)
slave.flush()
for z in zones1:
    slave.zone_wait(z, after_update25[z.name], equal=False, greater=True)
    slave.zone_verify(z)

t.end()
