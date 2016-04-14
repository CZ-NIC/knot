#!/usr/bin/env python3

from dnstest.test import Test
import dnstest.utils

t = Test()

ixfr_master = t.server("bind")
ixfr_slave = t.server("knot")

axfr_master = t.server("bind")
axfr_slave = t.server("knot")

zone = t.zone("example.com.", storage=".")

t.link(zone, ixfr_master, ixfr_slave, ixfr=True)
t.link(zone, axfr_master, axfr_slave, ixfr=False)

def prepare(master, slave, zone):
    # Wait for zones.
    serial = master.zone_wait(zone)
    slave.zone_wait(zone)

    # Update master file with the record (new SOA serial).
    master.update_zonefile(zone, version=1)
    master.reload()

    # Wait for zones and compare them.
    master_serial = master.zone_wait(zone, serial)
    return master_serial


def test(slave, zone, master_serial):
    slave_serial = slave.zone_wait(zone)

    return slave_serial == master_serial

t.start()

ixfr_serial = prepare(ixfr_master, ixfr_slave, zone)
axfr_serial = prepare(axfr_master, axfr_slave, zone)

t.sleep(10)

ixfr = test(ixfr_slave, zone, ixfr_serial)
axfr = test(axfr_slave, zone, axfr_serial)

dnstest.utils.detail_log("IXFR %s" % (not ixfr))
dnstest.utils.detail_log("AXFR %s" % (not axfr))
if ixfr or axfr:
    dnstest.utils.set_err("SEMANTIC CHECK")

t.end()
