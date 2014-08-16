#!/usr/bin/env python3

'''Test for TSIG functionality with DDNS. '''

from dnstest.test import Test

t = Test(tsig=True)

master = t.server("knot")
zone = t.zone("examPle.com", storage=".")
t.link(zone, master, ddns=True)

t.start()
master.zone_wait(zone)

up = master.update(zone)
up.add("test123.examPle.com.", "3600", "TXT", "test")
# Send signed update
up.send("NOERROR")

t.end()
