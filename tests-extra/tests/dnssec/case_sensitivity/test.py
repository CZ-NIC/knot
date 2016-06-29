#!/usr/bin/env python3

'''Test for no resigning if the zone is properly signed.'''

from dnstest.utils import set_err
from dnstest.test import Test
import subprocess

def patch_zone(t, server, zone, script):
    """
    Update zone file on a master server.
    """
    zone = zone[0]
    zonefile = "%s/master/%s" % (server.dir, zone.file_name)
    modify_script = "%s/modify.sh" % t.data_dir
    patch_script = "%s/%s" % (t.data_dir, script)
    subprocess.check_call([modify_script, zonefile, patch_script])

t = Test()

server = t.server("knot")
zone = t.zone("example.", storage=".")
t.link(zone, server)
server.dnssec(zone).enable = True

t.start()

serial = server.zone_wait(zone)

scripts = [
    ("insensitive RRs", "modify-insensitive.awk", False),
    ("NSEC RR", "modify-nsec.awk", True),
    ("LP RR", "modify-lp.awk", True),
]

for name, script, resign in scripts:
    t.sleep(1)
    server.flush()
    server.stop()
    patch_zone(t, server, zone, script)
    server.start()

    new_serial = server.zone_wait(zone)
    signed = new_serial != serial

    if signed != resign:
        set_err("Invalid state after %s change" % name)
        break

    serial = new_serial

t.stop()
