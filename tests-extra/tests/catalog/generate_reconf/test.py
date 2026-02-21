#!/usr/bin/env python3

'''Test of catalog zone reconfiguration.'''

from dnstest.test import Test
from dnstest.utils import compare, set_err, detail_log
from dnstest.libknot import libknot
import glob
import os
import random
import shutil
import time

USE_CTL = random.choice([True, False])

def ctl_begin(server):
    ctl = libknot.control.KnotCtl()
    ctl.connect(os.path.join(server.dir, "knot.sock"))
    return ctl

def ctl_cmd(ctl, **args):
    ctl.send_block(**args)
    return ctl.receive_block()

def ctl_add_zone(ctl, zone_name):
    ctl_cmd(ctl, cmd="zone-begin", zone=zone_name)
    ctl_cmd(ctl, cmd="zone-set", zone=zone_name, owner="@", ttl="3600", rtype="SOA", data="a. b. 1 2 3 4 5")
    ctl_cmd(ctl, cmd="zone-commit", zone=zone_name)

def ctl_end(ctl):
    ctl.send(libknot.control.KnotCtlType.END)
    ctl.close()

def mark_zone(server, zone):
    zone_name = zone[0].name
    ts = int(time.time() * 1000)
    server.zones[zone_name].zfile.append_rndTXT(f"_mark_{ts}_")
    return ts

def check_mark(server, zone, timestamp, present=True):
    t.sleep(1)
    zone_name = zone[0].name
    resp = server.dig(f"_mark_{timestamp}_.{zone_name}", "TXT")
    resp.check_rr(rtype="TXT") if present else resp.check_no_rr(rtype="TXT")

t = Test()

master = t.server("knot")
slave = t.server("knot")

zone1 = t.zone_rnd(1)
t.link(zone1, master, slave)
master.conf_zone(zone1).zonefile_sync = 0
slave.cat_hidden(zone1)

gen1 = t.zone("gen1.", exists=False)
t.link(gen1, master, slave)
master.cat_generate(gen1)
slave.cat_interpret(gen1)

t.start()

if USE_CTL:
    master.use_confdb = True
    master.gen_confile()
    master.ctl("conf-import %s" % master.confile, availability=False)
    master.stop()
    master.start()

master.zones_wait(zone1, use_ctl=True)
serial = slave.zones_wait(gen1, use_ctl=True)

# Add a new member to an existing generated catalog.

zone1_ts = mark_zone(master, zone1)

memb1 = t.zone_rnd(1)

if USE_CTL:
    ctl = ctl_begin(master)
    ctl_cmd(ctl, cmd="conf-begin")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="domain", data=memb1[0].name)
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="catalog-role", identifier=memb1[0].name, data="member")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="catalog-zone", identifier=memb1[0].name, data=gen1[0].name)
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="notify", identifier=memb1[0].name, data="knot2")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="acl", identifier=memb1[0].name, data="acl_test")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="acl", identifier=memb1[0].name, data="acl_knot2")
    ctl_cmd(ctl, cmd="conf-commit")
    ctl_add_zone(ctl, memb1[0].name)
    ctl_end(ctl)

    check_mark(master, zone1, zone1_ts, present=False)
else:
    t.link(memb1, master, slave)
    master.cat_member(memb1, gen1)
    slave.cat_hidden(memb1)

    master.gen_confile()
    master.reload()

    check_mark(master, zone1, zone1_ts)

serial = slave.zones_wait(gen1, serial, use_ctl=True)
slave.zones_wait(memb1, use_ctl=True)

# Add a second generated catalog along with its member and catalogize existing zone.

gen2 = t.zone("gen2.", exists=False)
memb2 = t.zone_rnd(1)

if USE_CTL:
    ctl = ctl_begin(master)
    ctl_cmd(ctl, cmd="conf-begin")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="domain", data=gen2[0].name)
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="catalog-role", identifier=gen2[0].name, data="generate")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="notify", identifier=gen2[0].name, data="knot2")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="acl", identifier=gen2[0].name, data="acl_test")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="acl", identifier=gen2[0].name, data="acl_knot2")

    ctl_cmd(ctl, cmd="conf-unset", section="zone", item="catalog-role", identifier=memb1[0].name)
    ctl_cmd(ctl, cmd="conf-unset", section="zone", item="catalog-zone", identifier=memb1[0].name)

    ctl_cmd(ctl, cmd="conf-set", section="zone", item="catalog-role", identifier=zone1[0].name, data="member")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="catalog-zone", identifier=zone1[0].name, data=gen2[0].name)

    ctl_cmd(ctl, cmd="conf-set", section="zone", item="domain", data=memb2[0].name)
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="catalog-role", identifier=memb2[0].name, data="member")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="catalog-zone", identifier=memb2[0].name, data=gen2[0].name)
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="notify", identifier=memb2[0].name, data="knot2")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="acl", identifier=memb2[0].name, data="acl_test")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="acl", identifier=memb2[0].name, data="acl_knot2")
    ctl_cmd(ctl, cmd="conf-commit")
    ctl_add_zone(ctl, memb2[0].name)
    ctl_end(ctl)

    ctl = ctl_begin(slave)
    ctl_cmd(ctl, cmd="conf-begin")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="domain", data=gen2[0].name)
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="catalog-role", identifier=gen2[0].name, data="interpret")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="catalog-template", identifier=gen2[0].name, data="catalog-default")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="catalog-template", identifier=gen2[0].name, data="catalog-signed")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="catalog-template", identifier=gen2[0].name, data="catalog-unsigned")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="master", identifier=gen2[0].name, data="knot1")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="acl", identifier=gen2[0].name, data="acl_test")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="acl", identifier=gen2[0].name, data="acl_knot1")
    ctl_cmd(ctl, cmd="conf-commit")
    ctl_end(ctl)
else:
    t.link(gen2, master, slave)
    master.cat_generate(gen2)
    slave.cat_interpret(gen2)

    t.link(memb2, master, slave)
    master.cat_member(memb2, gen2) # New zone
    slave.cat_hidden(memb2)

    master.cat_member(zone1, gen2) # Existing zone

    master.cat_member(memb1, gen1, remove=True) # Decataloged zone
    slave.cat_hidden(memb1, remove=True)
    slave.zones.pop(memb1[0].name) # Remove a relict of t.link() - explicit configuration

    master.gen_confile()
    slave.gen_confile()
    slave.reload()
    master.reload()

slave.zones_wait(gen1, use_ctl=True)
slave.zones_wait(gen2, use_ctl=True)
slave.zones_wait(memb2, use_ctl=True)
slave.zones_wait(zone1, use_ctl=True)
t.sleep(2)
resp = slave.dig(memb1[0].name, "SOA")
resp.check_no_rr(rtype="SOA") # REFUSED not reliable as it can return NXDOMAIN due to random zone names

# Move a member between generated catalogs

zone1_ts = mark_zone(master, zone1)

OK_XFR = random.choice([True, False]) # If true, the zone is correctly decataloged first.

if OK_XFR:
    master.ctl("zone-xfr-freeze %s" % gen1[0].name)
else:
    master.ctl("zone-xfr-freeze %s" % gen2[0].name)

if USE_CTL:
    ctl = ctl_begin(master)
    ctl_cmd(ctl, cmd="conf-begin")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="catalog-zone", identifier=memb2[0].name, data=gen1[0].name)
    ctl_cmd(ctl, cmd="conf-commit")
    ctl_end(ctl)

    check_mark(master, zone1, zone1_ts, present=False)
else:
    master.cat_member(memb2, gen2, remove=True)
    master.cat_member(memb2, gen1)

    master.gen_confile()
    master.reload()

    check_mark(master, zone1, zone1_ts)

t.sleep(2)
resp = slave.dig(memb2[0].name, "SOA")
if OK_XFR:
    resp.check_no_rr(rtype="SOA") # REFUSED not reliable as it can return NXDOMAIN due to random zone names

    master.ctl("zone-xfr-thaw %s" % gen1[0].name)
    slave.ctl("zone-refresh %s" % gen1[0].name)
else:
    resp.check_rr(rtype="SOA") # Memeber not removed

    master.ctl("zone-xfr-thaw %s" % gen2[0].name)
    slave.ctl("zone-refresh %s" % gen2[0].name)
    t.sleep(2)
    resp = slave.dig(memb2[0].name, "SOA")
    resp.check_no_rr(rtype="SOA") # Member permanently removed

    # Fix catalog inconsistency
    slave.ctl("zone-retransfer %s" % gen1[0].name)

slave.zones_wait(memb2, use_ctl=True)

# Catalog group change - verify the target template module is activated

zone1_ts = mark_zone(master, zone1)

resp = slave.dig(memb2[0].name, "SOA", udp=True)
resp.check(noflags="TC") # Module mod-noudp is not active

ctl = ctl_begin(slave)
ctl_cmd(ctl, cmd="conf-begin")
ctl_cmd(ctl, cmd="conf-set", section="template", identifier="catalog-signed", item="module", data="mod-noudp")
ctl_cmd(ctl, cmd="conf-commit")
ctl_end(ctl)

if USE_CTL:
    ctl = ctl_begin(master)
    ctl_cmd(ctl, cmd="conf-begin")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="catalog-group", identifier=memb2[0].name, data="catalog-signed")
    ctl_cmd(ctl, cmd="conf-commit")
    ctl_end(ctl)

    check_mark(master, zone1, zone1_ts, present=False)
else:
    master.cat_member(memb2, gen1, "catalog-signed")

    master.gen_confile()
    master.reload()

    check_mark(master, zone1, zone1_ts)

slave.zones_wait(memb2, use_ctl=True)
t.sleep(2)
resp = slave.dig(memb2[0].name, "SOA", dnssec=True, udp=False)
resp.check(rcode="NOERROR")
resp.check_count(1, "RRSIG") # Signing active

resp = slave.dig(memb2[0].name, "SOA", udp=True)
resp.check(flags="TC") # Module mod-noudp is active

# Include configuration file with a generated catalog member

if USE_CTL:
    zone1_ts = mark_zone(master, zone1)

    zone2 = t.zone("zone2.", exists=False)

    ctl = ctl_begin(master)
    ctl_cmd(ctl, cmd="conf-begin")
    ctl_cmd(ctl, cmd="conf-set", section="include", data=master.data_add(zone2[0].name + "conf", "."))
    ctl_cmd(ctl, cmd="conf-commit")
    ctl_add_zone(ctl, zone2[0].name)
    ctl_end(ctl)

    slave.zones_wait(zone2, use_ctl=True)

    check_mark(master, zone1, zone1_ts)

# Include configuration file with a generated catalog, add another zone, remove previous zone

if USE_CTL:
    zone1_ts = mark_zone(master, zone1)

    gen3 = t.zone("gen3.", exists=False)
    zone3 = t.zone("zone3.", exists=False)

    ctl = ctl_begin(master)
    ctl_cmd(ctl, cmd="conf-begin")
    ctl_cmd(ctl, cmd="conf-set", section="include", data=master.data_add(gen3[0].name + "conf", "."))

    ctl_cmd(ctl, cmd="conf-set", section="zone", item="domain", data=zone3[0].name)
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="catalog-role", identifier=zone3[0].name, data="member")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="catalog-zone", identifier=zone3[0].name, data=gen3[0].name)
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="notify", identifier=zone3[0].name, data="knot2")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="acl", identifier=zone3[0].name, data="acl_test")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="acl", identifier=zone3[0].name, data="acl_knot2")

    ctl_cmd(ctl, cmd="conf-unset", section="zone", identifier=zone2[0].name)
    ctl_cmd(ctl, cmd="conf-commit")
    ctl_add_zone(ctl, zone3[0].name)
    ctl_end(ctl)

    ctl = ctl_begin(slave)
    ctl_cmd(ctl, cmd="conf-begin")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="domain", data=gen3[0].name)
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="catalog-role", identifier=gen3[0].name, data="interpret")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="catalog-template", identifier=gen3[0].name, data="catalog-default")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="catalog-template", identifier=gen3[0].name, data="catalog-signed")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="catalog-template", identifier=gen3[0].name, data="catalog-unsigned")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="master", identifier=gen3[0].name, data="knot1")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="acl", identifier=gen3[0].name, data="acl_test")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="acl", identifier=gen3[0].name, data="acl_knot1")
    ctl_cmd(ctl, cmd="conf-commit")
    ctl_end(ctl)

    slave.zones_wait(gen3, use_ctl=True)
    slave.zones_wait(zone3, use_ctl=True)
    t.sleep(2)
    resp = slave.dig(zone2[0].name, "SOA")
    resp.check_no_rr(rtype="SOA")

    check_mark(master, zone1, zone1_ts)

# Reconfigure include-from

if USE_CTL:
    zone1_ts = mark_zone(master, zone1)

    cz = t.zone("cz.", storage=".")
    org_cz = t.zone("org.cz.", storage=".")

    for zf in glob.glob(t.data_dir + "/*.zone"):
        shutil.copy(zf, master.dir)

    ctl = ctl_begin(master)
    ctl_cmd(ctl, cmd="conf-begin")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="domain", data=org_cz[0].name)
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="domain", data=cz[0].name)
    ctl_cmd(ctl, cmd="conf-commit")

    t.sleep(1)
    resp = master.dig("org.cz", "DS")
    resp.check_rr(rtype="DS")

    ctl_cmd(ctl, cmd="conf-begin")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="include-from", identifier=cz[0].name, data=org_cz[0].name)
    ctl_cmd(ctl, cmd="conf-commit")

    t.sleep(1)
    resp = master.dig("org.cz", "DS")
    resp.check_no_rr(rtype="DS")

    # Enforce zone rebuild (catalog-group has no effect in this case)
    ctl_cmd(ctl, cmd="conf-begin")
    ctl_cmd(ctl, cmd="conf-set", section="zone", item="catalog-group", identifier=cz[0].name, data="catalog-signed")
    ctl_cmd(ctl, cmd="conf-commit")
    ctl_end(ctl)

    serial = master.zones_wait(cz, use_ctl=True)

    # Check the inter-zone links is updated by using them.
    ctl = ctl_begin(master)
    ctl_cmd(ctl, cmd="zone-begin", zone=org_cz[0].name)
    ctl_cmd(ctl, cmd="zone-set", zone=org_cz[0].name, owner="@", ttl="3600", rtype="TXT", data="test")
    ctl_cmd(ctl, cmd="zone-commit", zone=org_cz[0].name)
    ctl_end(ctl)

    serial = master.zones_wait(cz, serial, use_ctl=True)

    check_mark(master, zone1, zone1_ts, present=False)

t.end()
