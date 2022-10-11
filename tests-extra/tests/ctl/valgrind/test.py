#!/usr/bin/env python3

'''Test that tries to make Valgrind corrupt syscall return values'''

from dnstest.test import Test
from dnstest.utils import *

t = Test()

master = t.server("knot")
zone = t.zone("existing.", storage=".")
t.link(zone, master, ixfr=True)

t.start()

for i in range(50):
    master.backtrace()

t.end()
