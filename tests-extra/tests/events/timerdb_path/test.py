#!/usr/bin/env python3

"""
Tests for timer database specification in the config.
"""

from dnstest.test import Test
from dnstest.utils import set_err, detail_log
import os.path

t = Test(tsig=False, stress=False)

# three servers (default location, relative path, absolute path)

knot = t.server("knot")

knot_rel = t.server("knot")
knot_rel.timer_db = "custom-timers"

knot_abs = t.server("knot")
knot_abs.timer_db = os.path.join(knot_abs.dir, "custom-timers-2")

# the timer databases should be created when the server is stopped

SERVERS = [
  [ knot,     "timers" ],
  [ knot_rel, "custom-timers" ],
  [ knot_abs, "custom-timers-2" ],
]

for server, subdir in SERVERS:
    path = os.path.join(server.dir, subdir)
    if os.path.exists(path):
        raise AssertionError

t.start()
t.stop()

for server, subdir in SERVERS:
    path = os.path.join(server.dir, subdir, "data.mdb")
    if not os.path.exists(path):
        set_err("NO TIMER DATABASE")
        detail_log("path '%s'" % path)
