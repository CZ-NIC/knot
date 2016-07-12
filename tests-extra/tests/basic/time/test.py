#!/usr/bin/env python3

"""
Example test using libfaketime.
This test doesn't test anything.
TODO Should be deleted or moved.
"""


from dnstest.test import Test
from dnstest.faketime import FakeTime
import datetime

FakeTime.check()

with FakeTime() as ft:
    t = Test()
    master = t.server("knot")
    slave = t.server("knot")
    zone = t.zone("example.com")
    t.link(zone, master, slave)

    t.start()
    master.zone_wait(zone)
    slave.zone_wait(zone)

    master.stop()
    ft.set_time(datetime.datetime.now() + datetime.timedelta(days=45))
    slave.reload()

    t.end()
