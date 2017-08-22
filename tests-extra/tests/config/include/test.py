#!/usr/bin/env python3

'''Include zones through config files, tests-extra API, and CLI.'''

import os

from dnstest.libknot import libknot
from dnstest.test import Test
from dnstest.utils import *

t = Test()

ZONE1 = 'zone1.'
ZONE2 = 'zone2.'
ZONE3 = 'example.com.'
ZONE4 = 'zone4.'

knot = t.server("knot")
knot.include(ZONE1 + "conf", ".")
knot.include("server.conf", ".")
knot.include("empty.conf", ".")
knot.include(ZONE2 + "conf", ".")
added_file = knot.data_add(ZONE4 + "conf", ".")

zone = t.zone(ZONE3)
t.link(zone, knot)

ctl = libknot.control.KnotCtl()

t.start()

ctl.connect(os.path.join(knot.dir, "knot.sock"))

ctl.send_block(cmd="conf-begin")
resp = ctl.receive_block()

ctl.send_block(cmd="conf-set", section="include", data=added_file)
resp = ctl.receive_block()
# Cannot commit as it reloads the server without this include!

ctl.send_block(cmd="conf-get", section="zone")
resp = ctl.receive_block()

isset(ZONE1 in resp['zone'], ZONE1)
isset(ZONE2 in resp['zone'], ZONE2)
isset(ZONE3 in resp['zone'], ZONE3)
isset(ZONE4 in resp['zone'], ZONE4)

ctl.send_block(cmd="conf-commit")
resp = ctl.receive_block()

ctl.send_block(cmd="conf-read", section="server")
resp = ctl.receive_block()

isset('max-tcp-clients' in resp['server'], "server section item not set")
isset('5' in resp['server']['max-tcp-clients'], "server section item value not set")

ctl.send(libknot.control.KnotCtlType.END)
ctl.close()

t.end()
