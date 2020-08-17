#!/usr/bin/env python3

'''Test of IXFR freeze.'''

from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")
zone = t.zone_rnd(1, records=50)

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

master.ctl("zone-xfr-thaw", wait=True)
master.ctl("zone-notify")
slave.zone_wait(zone, serial_init)
t.xfr_diff(master, slave, zone)

t.end()
