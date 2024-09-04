#!/usr/bin/env python3

'''Test that tries to make Valgrind corrupt syscall return values'''

from dnstest.test import Test
from dnstest.utils import *

#t = Test(stress=False)
t = Test()

master = t.server("knot")
zone = t.zone_rnd(1, records=8)
t.link(zone, master, ixfr=True)

t.start()

for i in range(10):
#    try:
#        master.ctl("zone-freeze nonexisting-zone.")
#        master.ctl("conf-read")
#        master.ctl("zone-sign nonexisting-zone.")
#        master.ctl("status configure")
#        master.ctl("zone-purge nonexisting-zone.")
#        master.ctl("status vetrnik-s-kremem")
#        master.ctl("vetrnik-s-kremem")
        master.backtrace()
#    except Failed:
#        pass

t.end()
