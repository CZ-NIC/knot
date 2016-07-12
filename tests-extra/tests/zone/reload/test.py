#!/usr/bin/env python3

'''Test for reload of a changed zone (serial up, nochange, serial down). '''

from dnstest.test import Test
from dnstest.utils import set_err, detail_log
from dnstest.logwatch import LogWatchException

t = Test()

master = t.server("knot")

# Zone setup
zone = t.zone("serial.", storage=".")

t.link(zone, master, ixfr=True)

t.start()

# Load zones
serial = master.zone_wait(zone)

def reload_zone(serial, version):
    master.update_zonefile(zone, version)
    master.reload(wait_for_nzones=1)
    new_serial = master.zone_wait(zone)
    if new_serial != serial:
        set_err("SOA MISMATCH")
        detail_log("!Zone '%s' SOA serial %s != %s" % (zone[0].name, new_serial, serial))
        return
    resp = master.dig("new-record%d.%s" % (version, zone[0].name), "A")
    resp.check(rcode="NOERROR")

# Zone changes, serial increases (create changeset)
version = 1
serial = serial + 1
reload_zone(serial, version)

# Zone changes, serial doesn't change (no new changeset)
version += 1
reload_zone(serial, version)

# Zone changes, serial jumps out-of-range (journal is not applicable)
version += 1
serial = serial - 2
reload_zone(serial, version)

# Stop master.
master.stop()

t.end()
