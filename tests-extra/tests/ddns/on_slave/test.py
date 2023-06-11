#!/usr/bin/env python3

'''Test on-slave DDNS'''

from dnstest.utils import *
from dnstest.test import Test

t = Test()

master = t.server("knot")
slave  = t.server("knot")

zone = t.zone("example.com.")

t.link(zone, master, slave, ddns=True)

slave.dnssec(zone).enable = True
slave.ddns_master = ""

t.start()

serial0 = slave.zone_wait(zone)

up = slave.update(zone)
up.add("add1", 3600, "A", "1.2.3.4")
up.send()

serial1 = slave.zone_wait(zone, serial0)
master.zone_wait(zone, serial0, equal=True, greater=False)

up = master.update(zone)
up.add("add2", 3600, "A", "1.2.3.4")
up.send()

slave.zone_wait(zone, serial1)
q = slave.dig("add1.example.com.", "A")
q.check(rcode="NOERROR")
q = master.dig("add1.example.com.", "A")
q.check(rcode="NXDOMAIN")
q = slave.dig("add2.example.com.", "A")
q.check(rcode="NOERROR")

slave.flush(wait=True)
slave.zone_verify(zone)

t.end()
