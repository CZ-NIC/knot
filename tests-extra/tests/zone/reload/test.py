#!/usr/bin/env python3

'''Test for reload of a changed zone (serial up, nochange, serial down).'''

from dnstest.test import Test
from dnstest.utils import set_err, detail_log
import random

t = Test()

master = t.server("knot")

# Zone setup
zone = t.zone("serial.", storage=".")

t.link(zone, master, ixfr=True)

t.start()

# Load zones
serial = master.zone_wait(zone)

def reload_zone(version, exp_serial, exp_version, msg):
    master.update_zonefile(zone, version)

    opt = random.choice([1, 2, 3])
    if opt == 1:
        master.reload()
    if opt == 2:
        master.ctl("zone-reload " + zone[0].name) # the reload should fail -> no blocking mode, no error
        t.sleep(2)
    if opt == 3:
        master.ctl("-f zone-reload " + zone[0].name, wait=True)
        t.sleep(1) # forced zone-reload does *only schedule* LOAD event

    new_serial = master.zone_wait(zone)
    if new_serial != exp_serial:
        set_err("SOA MISMATCH %s (%d)" % (msg, opt))
        detail_log("!Zone '%s' SOA serial %s != %s" % (zone[0].name, new_serial, exp_serial))
        return
    resp = master.dig("new-record%d.%s" % (exp_version, zone[0].name), "A")
    resp.check(rcode="NOERROR")

# Zone changes, serial increases (create changeset)
reload_zone(1, serial + 1, 1, "create changeset")

# Zone changes, serial doesn't change (create changeset, increment serial automatically)
reload_zone(2, serial + 2, 2, "auto incremented")

# Zone changes, serial jumps out-of-range (journal is not applicable)
reload_zone(3, serial + 2, 2, "journal not applied")

# Stop master.
master.stop()

t.end()
