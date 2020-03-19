#!/usr/bin/env python3

'''Test for NSEC3 and delegation with and without opt-out'''

from dnstest.utils import *
from dnstest.test import Test
import random
import subprocess

zone_name = "example.com."

t = Test()

def check_deleg(deleg, nsec3_bitmap, opt_out_flag, msg):
    t.sleep(2)
    resp = master.dig(deleg + "." + zone_name, "A", dnssec=True, bufsize=4096)
    resp.check(rcode="NOERROR")
    if resp.resp.rcode() != 0:
        return
    first_nsec3 = str(resp.resp.authority[1]) # assert this is the first NSEC3 in the response
    first_bitmap = ' '.join(first_nsec3.split()[9:])
    check_log("NSEC3 bitmap '%s', expected '%s' for '%s'" % (first_bitmap, nsec3_bitmap, msg))
    if first_bitmap != nsec3_bitmap:
        set_err("NSEC3 bitmap for '%s'" % msg)

    first_flags = first_nsec3.split()[5];
    if first_flags != str(opt_out_flag):
        set_err("NSEC3 opt-out flag %s != %s for '%s'" % (first_flags, str(opt_out_flag), msg))

    detail_log(SEP)
    master.zone_backup(zone, flush=True)
    master.zone_verify(zone)

master = t.server("knot")
zone = t.zone(zone_name)

t.link(zone, master)

master.dnssec(zone).enable = True
master.dnssec(zone).nsec3 = True
master.dnssec(zone).nsec3_iters = 2
master.dnssec(zone).nsec3_salt_len = 8
master.dnssec(zone).nsec3_opt_out = False

t.start()

master.zones_wait(zone)
master.zone_backup(zone, flush=True)
master.zone_verify(zone)

# opt-out off, delegation added in changeset

up = master.update(zone)
up.add("deleg1", 3600, "NS", "nothing")
up.send("NOERROR")
check_deleg("deleg1", "NS", 0, "non-optout update")

# opt-out off, zone re-sign

master.ctl("zone-sign")
check_deleg("deleg1", "NS", 0, "non-optout re-sign")

# opt-out on, zone re-sign

master.dnssec(zone).nsec3_opt_out = True
master.gen_confile()
master.reload()
check_deleg("deleg1", "NS SOA MX RRSIG DNSKEY NSEC3PARAM CDS CDNSKEY", 1, "optout re-sign")

# opt-out on, delegation added in changeset

up = master.update(zone)
up.add("deleg2", 3600, "NS", "nothing")
up.add("a.b.c", 3600, "A", "1.2.3.4") # used later
up.send("NOERROR")
check_deleg("deleg2", "NS SOA MX RRSIG DNSKEY NSEC3PARAM CDS CDNSKEY", 1, "optout update")

# opt-out on, check empty-non-terminal above node that becomes opt-outed

up = master.update(zone)
up.add("a.b.c", 3600, "NS", "nothing")
up.delete("a.b.c", "A")
up.send("NOERROR")
master.zone_backup(zone, flush=True)
master.zone_verify(zone)

master.ctl("zone-sign")
master.zone_backup(zone, flush=True)
master.zone_verify(zone)

zf = master.zones[zone_name].zfile
zf_prev = zf.path + ".back" + str(zf.backup_num - 2)
zf_post = zf.path + ".back" + str(zf.backup_num - 1)
p = subprocess.run("diff %s %s  | egrep -v 'RRSIG|SOA|;;|---|^[0-9]' | wc -c | grep -q '^[0-2]$'" % (zf_prev, zf_post), shell=True)
if p.returncode > 0:
    set_err("NSEC3 changed upon re-sign")

t.end()
