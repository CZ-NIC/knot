#!/usr/bin/env python3

"""Basic checks of Additional section content."""

import os

from dnstest.libknot import libknot
from dnstest.test import Test

t = Test()

knot = t.server("knot")
zone = t.zone("test", storage=".")
t.link(zone, knot)

ctl = libknot.control.KnotCtl()

t.start()
serial = knot.zone_wait(zone)

ctl.connect(os.path.join(knot.dir, "knot.sock"))

# Initial test with default default-ttl = 3600

resp = knot.dig("test", "NS")
resp.check(rcode="NOERROR", rdata="ns.test.", ttl=7200)

resp = knot.dig("ns.test", "A")
resp.check(rcode="NOERROR", rdata="10.0.0.1", ttl=3600)

ctl.send_block(cmd="zone-begin")
resp = ctl.receive_block()
ctl.send_block(cmd="zone-set", zone=zone[0].name, owner="text1", rtype="TXT", data="test")
resp = ctl.receive_block()
ctl.send_block(cmd="zone-commit")
resp = ctl.receive_block()
serial = knot.zone_wait(zone, serial)

resp = knot.dig("text1.test", "TXT")
resp.check(rcode="NOERROR", rdata="test", ttl=3600)

# Set default-ttl to 120

ctl.send_block(cmd="conf-begin")
resp = ctl.receive_block()
ctl.send_block(cmd="conf-set", section="zone", item="default-ttl",
               identifier=zone[0].name, data="120")
resp = ctl.receive_block()
knot.zones[zone[0].name].zfile.update_soa(serial=serial+1)
ctl.send_block(cmd="conf-commit")
resp = ctl.receive_block()
serial = knot.zone_wait(zone, serial)

# Check the modified default-ttl affects the loaded zone

resp = knot.dig("test", "NS")
resp.check(rcode="NOERROR", rdata="ns.test.", ttl=7200)

resp = knot.dig("ns.test", "A")
resp.check(rcode="NOERROR", rdata="10.0.0.1", ttl=120)

ctl.send_block(cmd="zone-begin")
resp = ctl.receive_block()
ctl.send_block(cmd="zone-set", zone=zone[0].name, owner="text2", rtype="TXT", data="test")
resp = ctl.receive_block()
ctl.send_block(cmd="zone-commit")
resp = ctl.receive_block()
serial = knot.zone_wait(zone, serial)

resp = knot.dig("text2.test", "TXT")
resp.check(rcode="NOERROR", rdata="test", ttl=120)

ctl.send(libknot.control.KnotCtlType.END)
ctl.close()

t.stop()
