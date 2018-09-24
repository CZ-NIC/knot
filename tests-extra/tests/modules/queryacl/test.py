#!/usr/bin/env python3

'''Test for the queryacl module'''

from dnstest.utils import *
from dnstest.test import Test
from dnstest.libknot import libknot
from dnstest.module import ModQueryacl

import random

t = Test(address=4)

knot = t.server("knot")
zones = t.zone_rnd(3, dnssec=False)
t.link(zones, knot)

ctl = libknot.control.KnotCtl()

t.start()

knot.clear_modules(None)
knot.add_module(zones[0], ModQueryacl(address=["127.0.0.1/32", "127.0.0.2/32"]))
knot.add_module(zones[1], ModQueryacl(interface=["127.0.0.1/32", "127.0.0.2/32"]))
knot.add_module(zones[2], ModQueryacl(address=["127.0.0.1/32", "127.0.0.2/32"], interface=["127.0.0.1/32", "127.0.0.2/32"]))
knot.gen_confile()
knot.reload()
knot.zones_wait(zones)

ctl.connect(os.path.join(knot.dir, "knot.sock"))
ctl.send_block(cmd="conf-begin")
ctl.receive_block()
port = str(knot.port)
ctl.send_block(cmd="conf-set", section="server", item="listen", data="127.0.0.1@"+port)
ctl.receive_block()
ctl.send_block(cmd="conf-set", section="server", item="listen", data="127.0.0.2@"+port)
ctl.receive_block()
ctl.send_block(cmd="conf-set", section="server", item="listen", data="127.0.0.3@"+port)
ctl.receive_block()
ctl.send_block(cmd="conf-commit")
ctl.receive_block()

# Test just address ACL.
resp = knot.dig(zones[0].name, "SOA", addr="127.0.0.3", source="127.0.0.3")
resp.check(rcode="NOTAUTH")
resp = knot.dig(zones[0].name, "SOA", addr="127.0.0.3", source="127.0.0.2")
resp.check(rcode="NOERROR")
resp = knot.dig(zones[0].name, "SOA", addr="127.0.0.2", source="127.0.0.3")
resp.check(rcode="NOTAUTH")
resp = knot.dig(zones[0].name, "SOA", addr="127.0.0.2", source="127.0.0.2")
resp.check(rcode="NOERROR")

# Test just interface ACL.
resp = knot.dig(zones[1].name, "SOA", addr="127.0.0.3", source="127.0.0.3")
resp.check(rcode="NOTAUTH")
resp = knot.dig(zones[1].name, "SOA", addr="127.0.0.3", source="127.0.0.2")
resp.check(rcode="NOTAUTH")
resp = knot.dig(zones[1].name, "SOA", addr="127.0.0.2", source="127.0.0.3")
resp.check(rcode="NOERROR")
resp = knot.dig(zones[1].name, "SOA", addr="127.0.0.2", source="127.0.0.2")
resp.check(rcode="NOERROR")

# Test both address and interface ACL.
resp = knot.dig(zones[2].name, "SOA", addr="127.0.0.3", source="127.0.0.3")
resp.check(rcode="NOTAUTH")
resp = knot.dig(zones[2].name, "SOA", addr="127.0.0.3", source="127.0.0.2")
resp.check(rcode="NOTAUTH")
resp = knot.dig(zones[2].name, "SOA", addr="127.0.0.2", source="127.0.0.3")
resp.check(rcode="NOTAUTH")
resp = knot.dig(zones[2].name, "SOA", addr="127.0.0.2", source="127.0.0.2")
resp.check(rcode="NOERROR")

t.end()
