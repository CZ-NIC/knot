#!/usr/bin/env python3

'''Test for loading non-existing zone file'''

from dnstest.test import Test

t = Test()

master = t.server("knot")

zones = t.zone("notexist.", exists=False) + t.zone("wild.")

t.link(zones, master)

t.start()

# Stop master.
master.stop()

t.end()
