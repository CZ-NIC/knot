#!/usr/bin/env python3

'''Test of IXFR freeze.'''

from dnstest.test import Test
from dnstest.utils import *

t = Test()

master = t.server("knot")
slave = t.server("knot")
zone = t.zone_rnd(1, records=(30 if master.valgrind else 300))

t.link(zone, master, slave)

t.start()

serial_init = master.zone_wait(zone)
slave.zone_wait(zone)

master.ctl("zone-xfr-freeze", wait=True)
master.random_ddns(zone, allow_empty=False)
t.sleep(4)

resp = master.dig(zone[0].name, "AXFR", tries=1)
resp.check_xfr(rcode="REFUSED")

resp = slave.dig(zone[0].name, "SOA")
serial = resp.soa_serial()
if serial != serial_init:
    set_err("SOA serial mismatch")
    detail_log("SOA serial mismatch %d != %d" % (serial, serial_init))

master.stop()

master.dnssec(zone).enable = True
master.dnssec(zone).algorithm = "RSASHA512"
master.disable_notify = True
master.gen_confile()

master.start()
master.zone_wait(zone)
slave.ctl("zone-refresh")

resp = master.dig(zone[0].name, "AXFR", tries=1)
resp.check_xfr(rcode="REFUSED")

t.sleep(3)

resp = slave.dig(zone[0].name, "SOA")
serial = resp.soa_serial()
if serial != serial_init:
    set_err("SOA serial mismatch 2")
    detail_log("SOA serial mismatch2 %d != %d" % (serial, serial_init))

master.ctl("zone-sign")
master.ctl("zone-xfr-thaw", wait=True)
slave.ctl("zone-refresh")

t.sleep(3)
resp = slave.dig(zone[0].name, "SOA")
serial = resp.soa_serial()
if serial <= serial_init:
    set_err("SOA serial mismatch 3")
    detail_log("SOA serial mismatch3 %d <= %d" % (serial, serial_init))

t.end()
