#!/usr/bin/env python3

'''Test of key import from Bind9 in various roll-over stages'''

import copy
from dnstest.test import Test
from dnstest.utils import *

def wait_for_dnskey_count(t, server, zone, dnskey_count, timeout):
    rtime = 0.0
    while True:
        qdnskeyrrsig = server.dig(zone.name, "DNSKEY", dnssec=True, bufsize=4096)
        found_dnskeys = qdnskeyrrsig.count("DNSKEY")
        if found_dnskeys == dnskey_count:
            break
        rtime = rtime + 0.1
        t.sleep(0.1)
        if rtime > timeout:
            set_err("TIMEOUT DNSKEYs %d not %d" % (found_dnskeys, dnskey_count))
            break

def same_dnskey_count(t, server1, server2, zone, i, msg, timeout):
    s1d = server1.dig(zone.name, "DNSKEY", dnssec=True, bufsize=4096)
    s1c = s1d.count("DNSKEY")
    s2d = server2.dig(zone.name, "DNSKEY", dnssec=True, bufsize=4096)
    s2c = s2d.count("DNSKEY")
    if s1c != s2c:
        if timeout > 0:
            t.sleep(timeout)
            same_dnskey_count(t, server1, server2, zone, i, msg, 0)
        else:
            set_err("DNSKEY COUNT %d != %d (%s) [%s] (%s)" % (s1c, s2c, zone.name, str(i), msg))
            detail_log("DNSKEY COUNT %d != %d (%s) [%s] (%s)" % (s1c, s2c, zone.name, str(i), msg))

t = Test()

bind = t.server("bind")
knot = t.server("knot")
zones = t.zone_rnd(4, dnssec=False, ttl=3, records=6)

t.link(zones, bind)

def cds_submission(zones, timeout):
    bind_zones = { z.name: z for z in zones }
    knot_zones = { z.name: z for z in zones if z.name in knot.zones }
    for i in range(timeout):
        t.sleep(1)
        for z in zones:
            if z.name in bind_zones:
                try:
                    bind_keys = []
                    resp = bind.dig(z.name, "CDS")
                    for rd in resp.resp.answer[0].to_rdataset(): # if none, this fires exception
                        bind_keys.append(rd.to_text().split(' ')[0])
                    for k in bind_keys:
                        bind.ctl("dnssec -checkds -key %s published %s" % (k, z.name), availability=False)
                    bind_zones.pop(z.name)
                except:
                    pass
            if z.name in knot_zones:
                try:
                    knot.ctl("zone-ksk-submitted " + z.name)
                    knot_zones.pop(z.name)
                except:
                    pass
        if len(bind_zones) == 0 and len(knot_zones) == 0:
            return
    set_err("TIMEOUT CDSs")

def knot_dnskey_checks(t, msg, zones, timeout):
    for i, z in reversed(list(enumerate(zones))):
        if z.name in knot.zones:
            same_dnskey_count(t, bind, knot, knot.zones[z.name], i, msg, timeout)

def clone_policy(zone):
    knot.zones[zone.name].dnssec = copy.copy(bind.zones[zone.name].dnssec)
    knot.zones[zone.name].dnssec.ksk_lifetime -= 2 * int(knot.zones[zone.name].dnssec.dnskey_ttl)

def knot_import_zone(zone):
    if zone.name not in knot.zones:
        t.link([zone], knot)
    clone_policy(zone)
    knot.key_import_bind(zone.name)
    knot.gen_confile()
    try:
        knot.reload()
    except:
        knot.start()

for z in zones:
    bind.dnssec(z).enable = True
    bind.dnssec(z).propagation_delay = "2"
    bind.dnssec(z).dnskey_ttl = "3"
    bind.dnssec(z).zone_max_ttl = "4"
    bind.dnssec(z).ksk_lifetime = 40
    bind.dnssec(z).rrsig_lifetime = "8"
    bind.dnssec(z).rrsig_refresh = "4"
    bind.dnssec(z).rrsig_prerefresh = "1"
    bind.dnssec(z).ksk_sbm_check_interval = 1

t.generate_conf()
bind.start()
serials = bind.zones_wait(zones)
#cds_submission(zones, 10)

t.link([ zones[0] ], knot)
kdb = knot.zones[zones[0].name].zfile.key_dir_bind
prepare_dir(os.path.dirname(kdb))
os.symlink(bind.keydir, kdb)

serials = bind.zones_wait(zones)
knot_import_zone(zones[0])
knot.zone_wait(zones[0])
knot_dnskey_checks(t, "INIT", zones, 0)

knot_import_zone(zones[1])
for z in zones:
    wait_for_dnskey_count(t, bind, z, 3, 40)
knot_dnskey_checks(t, "PUBLISH", zones, 2)

# Following sections are not properly functioning due to Bind's undeterministic behaviour around KSK submission. It keeps publishing CDSs for old keys, even retired ones, and does not follow KSK roll-over pattern.

#cds_submission(zones, 10)

#knot_import_zone(zones[2])
#wait_for_dnskey_count(t, bind, zones[2], 2, 40)
#knot_dnskey_checks(t, "RETIRE", zones, 2)

#knot_import_zone(zones[3])
#t.sleep(2)
#knot_dnskey_checks(t, "END", zones[3:], 0)

t.end()
