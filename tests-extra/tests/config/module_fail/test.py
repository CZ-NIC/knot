#!/usr/bin/env python3

'''Check module failures when reloading zone.'''

from dnstest.libknot import libknot
from dnstest.test import Test
from dnstest.module import ModWhoami
from dnstest.module import ModOnlineSign
from dnstest.utils import *

ctl = libknot.control.KnotCtl()

def check_zone(server, zone, alive):
    try:
        ctl = libknot.control.KnotCtl()
        ctl.connect(os.path.join(server.dir, "knot.sock"))

        ctl.send_block(cmd="zone-stats", zone=zone[0].name)
        try:
            stats = ctl.receive_stats()
        except:
            isset(not alive, "zone not active")
        else:
            isset(alive, "zone active")
    finally:
        try:
            ctl.send(libknot.control.KnotCtlType.END)
            ctl.close()
        except:
            pass

t = Test()

ModWhoami.check()
ModOnlineSign.check()

knot = t.server("knot")
zone1 = t.zone_rnd(1)
zone2 = t.zone_rnd(1)
t.link(zone1 + zone2, knot)

knot.dnssec(zone1).enable = True

# Try to start the server with invalid module configuration (global module not allowed).

knot.add_module(None, ModWhoami())
try:
    t.start()
except Failed:
    t.stop()
else:
    set_err("SERVER STARTED")

# Reload the server with invalid module configuration.

knot.clear_modules(zone=None)
t.start()
t.sleep(0.5)

knot.add_module(None, ModWhoami())
t.generate_conf()
try:
    knot.reload()
except Failed:
    knot.stop()
else:
    set_err("SERVER RELOADED")

# Start the server without any module configured.

knot.clear_modules(zone=None)
t.generate_conf()
knot.start()
knot.zones_wait(zone1 + zone2)
t.sleep(0.5)
check_zone(knot, zone1, True)
check_zone(knot, zone2, True)

# Try to add an invalid zone module (online signing not compatible with normal signing).

knot.add_module(zone1, ModOnlineSign())
t.generate_conf()
knot.reload()
t.sleep(0.5)
check_zone(knot, zone1, False)
check_zone(knot, zone2, True)

t.end()
