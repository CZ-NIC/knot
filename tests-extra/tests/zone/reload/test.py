#!/usr/bin/env python3

'''Test for reload of a changed zone (serial up, nochange, serial down). '''

from dnstest.test import Test
from dnstest.utils import set_err, detail_log

t = Test()

master = t.server("knot")

# Zone setup
zone = t.zone("serial.", storage=".")

t.link(zone, master, ixfr=True)

t.start()

# Load zones
serial = master.zone_wait(zone)

def reload_zone(serial, version, exp_serial, exp_version):
    master.update_zonefile(zone, version)
    master.reload()
    new_serial = master.zone_wait(zone)
    if new_serial != exp_serial:
        set_err("SOA MISMATCH")
        detail_log("!Zone '%s' SOA serial %s != %s" % (zone[0].name, new_serial, exp_serial))
        return
    resp = master.dig("new-record%d.%s" % (exp_version, zone[0].name), "A")
    resp.check(rcode="NOERROR")

# Zone changes, serial increases (create changeset)
version = 1
serial = serial + 1
reload_zone(serial, version, serial, version)

# Zone changes, serial doesn't change (no new changeset)
version += 1
reload_zone(serial, version, serial, version - 1)

# Zone changes, serial jumps out-of-range (journal is not applicable)
version += 1
reload_zone(serial - 2, version, serial, version - 2)

# Stop master.
master.stop()

t.end()
