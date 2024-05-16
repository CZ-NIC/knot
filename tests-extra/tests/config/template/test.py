#!/usr/bin/env python3

'''Test for configuration zone templates'''

import os

from dnstest.libknot import libknot
from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")
zones = t.zone_rnd(2, records=5, dnssec=False)
for z in zones:
    z.name = z.name.lower()

t.link(zones, master, slave, ixfr=True)

ctl = libknot.control.KnotCtl()

t.start()

serials_init = master.zones_wait(zones)
slave.zones_wait(zones)

ctl.connect(os.path.join(master.dir, "knot.sock"))
ctl.send_block(cmd="conf-begin")
resp = ctl.receive_block()

# Move notify setting from zones to the default template.
ctl.send_block(cmd="conf-get", section="zone", item="notify", identifier=zones[0].name)
resp = ctl.receive_block()
for val in resp['zone'][zones[0].name]['notify']:
    ctl.send_block(cmd="conf-set", section="template", identifier="default", item="notify", data=val)
    resp = ctl.receive_block()
ctl.send_block(cmd="conf-unset", section="zone", item="notify")
resp = ctl.receive_block()

# Override template setting with the default (none) for the first zone.
ctl.send_block(cmd="conf-set", section="zone", item="notify", identifier=zones[0].name, data="")
resp = ctl.receive_block()

ctl.send_block(cmd="conf-commit")
resp = ctl.receive_block()
ctl.send(libknot.control.KnotCtlType.END)
ctl.close()

# Modify the zones and check that notify doesn't work for the first zone.
serials_prev = serials_init
serial1 = serials_init[zones[0].name]
for i in range(2):
    for zone in zones:
        master.update_zonefile(zone, random=True)
    master.ctl('zone-reload')

    serials_prev = master.zones_wait(zones, serials_prev)
    slave.zone_wait(zones[1], serials_prev[zones[1].name], equal=True, greater=False)
    t.sleep(1)
    slave.zone_wait(zones[0], serial1, equal=True, greater=False)

t.end()
