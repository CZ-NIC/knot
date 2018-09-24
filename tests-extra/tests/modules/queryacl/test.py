#!/usr/bin/env python3

'''Test for the queryacl module'''

from dnstest.utils import *
from dnstest.test import Test
from dnstest.libknot import libknot

import random

t = Test()

knot = t.server("knot")
zones = t.zone(".") + t.zone("records.")

t.link(zones, knot)

ctl = libknot.control.KnotCtl()

t.start()

ctl.connect(os.path.join(knot.dir, "knot.sock"))
ctl.send_block(cmd="conf-begin")
ctl.receive_block()
port = str(knot.port)
ctl.send_block(cmd="conf-set", section="server", item="listen", data="::1@"+port)
ctl.receive_block()
ctl.send_block(cmd="conf-set", section="server", item="listen", data="127.0.0.1@"+port)
ctl.receive_block()
ctl.send_block(cmd="conf-commit")
ctl.receive_block()

resp = knot.dig("records.", "SOA", addr="::1", source="127.0.0.1")
print(resp.resp.to_text())

resp = knot.dig("records.", "SOA", addr="127.0.0.1")
print(resp.resp.to_text())

t.end()
