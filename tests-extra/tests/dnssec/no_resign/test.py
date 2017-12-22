#!/usr/bin/env python3

'''Test for no re-signing if the zone is properly signed.'''

from dnstest.utils import *
from dnstest.test import Test
import dns
import shutil

# Changes in NSEC allowed due to case changes (Knot lowercases all owners).
def only_nsec_changed(server, zone, serial):
   resp = master.dig(nsec_zone, "IXFR", serial=serial)
   for msg in resp.resp:
       for rr in msg.answer:
            if rr.rdtype not in [dns.rdatatype.SOA, dns.rdatatype.NSEC, dns.rdatatype.RRSIG]:
                return False
            if rr.rdtype == dns.rdatatype.RRSIG:
                if (not rr.match(rr.name, rr.rdclass, dns.rdatatype.RRSIG, dns.rdatatype.NSEC)) and \
                   (not rr.match(rr.name, rr.rdclass, dns.rdatatype.RRSIG, dns.rdatatype.SOA)):
                    # RRSIG covering something else than NSEC or SOA.
                    return False
   return True

t = Test()

master = t.server("knot")

nsec_zone = t.zone_rnd(1, dnssec=True, nsec3=False)
nsec3_zone = t.zone_rnd(1, dnssec=True, nsec3=0)
static_zone = t.zone("example.", storage=".")
t.link(nsec_zone, master)
t.link(nsec3_zone, master)
t.link(static_zone, master)

master.dnssec(nsec_zone).alg = "rsasha1"
master.dnssec(nsec3_zone).alg = "rsasha1"
master.dnssec(nsec3_zone).nsec3 = True
master.dnssec(static_zone).alg = "rsasha1"

# install KASP db
shutil.copytree(os.path.join(t.data_dir, "keys"), master.keydir)

t.start()

# Get zone serial.
old_nsec_serial = master.zone_wait(nsec_zone)
old_nsec3_serial = master.zone_wait(nsec3_zone)
old_static_serial = master.zone_wait(static_zone)

# Enable autosigning.
master.dnssec(nsec_zone).enable = True
master.dnssec(nsec3_zone).enable = True
master.dnssec(static_zone).enable = True
master.dnssec(nsec_zone).manual = True
master.dnssec(nsec3_zone).manual = True
master.dnssec(static_zone).manual = True
master.key_import_bind(nsec_zone[0].name)
master.key_import_bind(nsec3_zone[0].name)
master.gen_confile()
master.reload()

t.sleep(10)

new_nsec_serial = master.zone_wait(nsec_zone)
new_nsec3_serial = master.zone_wait(nsec3_zone)
new_static_serial = master.zone_wait(static_zone)

# Check if the zones are re-signed.
if old_nsec_serial != new_nsec_serial:
    if not only_nsec_changed(master, nsec_zone, old_nsec_serial):
        set_err("NSEC zone got re-signed")

compare(old_nsec3_serial, new_nsec3_serial, "NSEC3 zone got re-signed")
compare(old_static_serial, new_static_serial, "static zone got re-signed")

t.stop()
