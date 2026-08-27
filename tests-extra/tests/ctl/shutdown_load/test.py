#!/usr/bin/env python3

'''Test on server shutdown when a zone is loading.'''

import datetime
import psutil
from dnstest.libknot import libknot
from dnstest.test import Test
from dnstest.utils import *

t = Test()

knot = t.server("knot")
zone = t.zone_rnd(1, records=(40 if knot.valgrind else 800))
t.link(zone, knot)

knot.dnssec(zone).enable = True
knot.dnssec(zone).algorithm = "rsasha512"
knot.dnssec(zone).zsk_size = "4096"
knot.dnssec(zone).nsec3 = True
knot.dnssec(zone).signing_threads = 1

knot.conf_srv().async_start = True

t.start()

#print(knot.proc.pid)

# Three possibilities how to shut down:
#knot.stop()
knot.ctl("stop")
#knot.proc.terminate()

t.sleep(10)
#print(datetime.datetime.now())

#if psutil.pid_exists(knot.proc.pid):
if not knot.log_search("shutting down"):
    set_err("Server still running")
    knot.backtrace()

#t.sleep(15)

t.end()
