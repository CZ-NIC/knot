#!/usr/bin/env python3

from dnstest.test import Test

t = Test()

master = t.server("knot")
tested = t.server("knot")
slave = t.server("knot")

zone = t.zone("example.com.")

t.link(zone, master,  tested, ixfr=True)
t.link(zone, tested,  slave,  ixfr=True)

t.start()

serials_init = master.zones_wait(zone)
slave.zones_wait(zone)

up = master.update(zone)
up.add("suppnot1", 3600, "A", "1.2.3.4")
up.send()

slave.zones_wait(zone, serials_init)

req = slave.dig("suppnot1.example.com.", "A")
req.check(rcode="NOERROR")

tested.ctl("conf-begin")
tested.ctl("conf-set remote[knot1].suppr-notify-after-xfr on")
tested.ctl("conf-commit")

up = master.update(zone)
up.add("suppnot2", 3600, "A", "1.2.3.4")
up.send()

t.sleep(10)

req = slave.dig("suppnot2.example.com.", "A")
req.check(rcode="NXDOMAIN")

t.end()
