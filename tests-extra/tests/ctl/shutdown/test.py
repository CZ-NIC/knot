#!/usr/bin/env python3

'''Test on server shutdown when a zone transaction is open.'''

import psutil
from dnstest.libknot import libknot
from dnstest.test import Test
from dnstest.utils import *

t = Test()

knot = t.server("knot")
zone = t.zone("example.com.")
t.link(zone, knot)

ctl = libknot.control.KnotCtl()

t.start()

ctl.connect(os.path.join(knot.dir, "knot.sock"))
ctl.send_block(cmd="zone-begin", zone=zone[0].name)
ctl.receive_block()
ctl.send(libknot.control.KnotCtlType.END)
ctl.close()

knot.stop()
t.sleep(1)

if psutil.pid_exists(knot.proc.pid):
    set_err("Server still running")

t.end()
