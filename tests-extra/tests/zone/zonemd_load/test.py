#!/usr/bin/env python3

'''Various zone file loading with ZONEMD generation enabled.'''

import random

from dnstest.test import Test
from dnstest.utils import *

t = Test()

master = t.server("knot")
slave = t.server("knot")

ZONE = "example.com."
zone = t.zone(ZONE)
t.link(zone, master, slave)

master.zonefile_sync = -1
master.zonemd_generate = "zonemd-sha384"
slave.zonemd_verify = True

VALIDATE_ZONEFILE = random.choice([True, False])

t.start()

for load in ["whole", "difference", "difference-no-serial"]:
    for dnssec in [False, True]:
        check_log("ZONE FILE LOAD: " + load + ", DNSSEC: " + str(dnssec) + ", valide ZF: " + str(VALIDATE_ZONEFILE))

        master.ctl("-f zone-purge +journal +timers +kaspdb " + ZONE)
        master.zonefile_load = load
        master.zones[ZONE].journal_content = "all" if load == "difference-no-serial" else "changes"
        master.zones[ZONE].dnssec.enable = dnssec
        master.gen_confile()
        master.stop()
        master.start()

        # Check if successfully transfered and valid ZONEMD.
        serial = master.zones_wait(zone)
        if dnssec and VALIDATE_ZONEFILE:
            master.zone_backup(zone, flush=True)
            master.zone_verify(zone)

        slave.ctl("-f zone-purge " + ZONE)
        slave.reload()
        new_serials = slave.zones_wait(zone)

        # Check if unchanged serial upon restart.
        master.stop()
        master.start()
        master.zones_wait(zone, serial, equal=True, greater=False)

        # Check if unchanged serial upon zone-reload.
        master.ctl("zone-reload " + ZONE)
        master.zones_wait(zone, serial, equal=True, greater=False)

t.end()
