#!/usr/bin/env python3

'''Test of load/dump behavior with malformed record(s) (e.g. 2-byte A).'''

from dnstest.test import Test
from dnstest.utils import *
import os
import shutil

rrs = {
    'a': 'C000',
    'svcb': '0001000003000403646F68',
    'https': '0001',
    'cds': '0101',
    'nsec3': '01000000',
    'nsec3param': '01000000',
    'zonemd': '000000020101d564',
}

zns_masl = [ "a.short.", "svcb.short.", "nsec3param.short.", "zonemd.short." ]

def add_owner(zn):
    if zn == 'nsec3.short.':
        return '5rv3hj8n5hjgjckqd09lssc266f6mtcf' # knsec3hash 1 0 0 - nsec3.short.
    elif zn == 'nsec3.empty.':
        return 'f06u65p6uholedjsnl6gvdftpmc0cfo0' # knsec3hash 1 0 0 - nsec3.empty.
    else:
        return zn

def add_rr(zn):
    (what, how) = zn.split(".")[:2]
    res = add_owner(zn) + " " + what + " \\# "
    if how == "empty":
        return res + "0"
    else:
        return res + "%d %s" % (len(rrs[what]) / 2, rrs[what])

zns_short = [ '%s.short' % x for x in rrs ]
zns_empty = [ '%s.empty' % x for x in rrs ]

t = Test()

master = t.server("knot")
slave = t.server("knot")
zfloader = t.server("knot")

zones_short = sum([t.zone(zn, storage=".", exists=False) for zn in zns_short], [])
zones_empty = sum([t.zone(zn, storage=".", exists=False) for zn in zns_empty], [])
zones_all = zones_short + zones_empty
zones_masl = [ x for x in zones_short if x.name in zns_masl ]
zones_zfld = zones_all

t.link(zones_masl, master, slave)
t.link(zones_zfld, zfloader)

master.conf_zone(zones_masl).journal_content = "all"
master.conf_zone(zones_masl).semantic_checks = False

zfloader.conf_zone(zones_all).zonefile_load = "difference-no-serial"
zfloader.conf_zone(zones_all).journal_content = "all"
zfloader.conf_zone(zones_all).semantic_checks = True

for s in [slave, zfloader]:
    for z in zones_all:
        if "zonemd" in z.name:
            s.conf_zone(z).zonemd_verify = True

for z in zones_all:
    for s in [ master, zfloader]:
        if z.name in s.zones:
            shutil.copyfile(os.path.join(t.data_dir, "template.zone"), s.zones[z.name].zfile.path)

t.start()

serials = master.zones_wait(zones_masl)
for z in zones_masl:
    master.ctl("zone-begin " + z.name)
    try:
        master.ctl("zone-set " + z.name + " " + add_rr(z.name))
        if z.name != "svcb.short." and z.name != 'zonemd.short.':
            detail_log("Allowed malformed generic RR in ctl " + z.name)
            set_err("Allowed malformed generic RR in ctl " + z.name)
    except:
        master.ctl("-f zone-set " + z.name + " " + add_rr(z.name))
    if 'nsec3.' in z.name:
        master.ctl("zone-set %s @ NSEC3PARAM 1 0 0 -" % z.name)
    try:
        master.ctl("zone-commit " + z.name)
    except:
        if 'nsec3param' in z.name:
            pass
        else:
            raise


master.zones_wait([x for x in zones_masl if 'nsec3param' not in x.name], serials)
t.sleep(2)
serials["svcb.short."] += 1 # SVCB is not malformed to the degree that it would fail canonicalization
slave.zones_wait([x for x in zones_masl if 'zonemd' not in x.name], serials, equal=True, greater=False)
master.ctl("zone-flush", wait=True)

for z in zones_masl:
    if 'nsec3param' in z.name or 'zonemd' in z.name:
        continue

    generic_found = False
    with open(master.zones[z.name].zfile.path, "r") as f:
        for l in f:
            if "\\# " in l:
                generic_found = True
    if not generic_found:
        detail_log("No generic RR in " + z.name)
        set_err("No generic RR in " + z.name)

    resp = master.dig("dns1." + z.name, "A")
    resp.check(rcode="NOERROR", rdata="192.0.2.1")

resp = master.dig("a.short.", "A")
resp.check(rcode="SERVFAIL")

try:
    resp = master.dig("svcb.short.", "SVCB", timeout=0.3)
    resp.check(rcode="NOERROR")
except Failed:
    pass

for z in zones_zfld:
    if z.name in master.zones and 'nsec3param' not in z.name:
        shutil.copyfile(master.zones[z.name].zfile.path, zfloader.zones[z.name].zfile.path)
    else:
        with open(zfloader.zones[z.name].zfile.path, "a") as f:
            f.write(add_rr(z.name) + "\n")
            if 'nsec3.' in z.name:
                f.write("@ NSEC3PARAM 1 0 0 -\n")

    try:
        zfloader.ctl("zone-reload " + z.name, wait=True)
        if z.name != "svcb.short." and z.name != 'zonemd.short.':
            detail_log("Allowed malformed generic RR in zone file " + z.name)
            set_err("Allowed malformed generic RR in zone file " + z.name)
    except:
        pass

t.end()
