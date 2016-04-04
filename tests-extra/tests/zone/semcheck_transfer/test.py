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


def test(master, slave, zone):
    # Wait for zones.
    serial = master.zone_wait(zone)
    slave.zone_wait(zone)

    # Update master file with the record (new SOA serial).
    master.update_zonefile(zone, version=1)
    master.reload()

    # Wait for zones and compare them.
    master_serial = master.zone_wait(zone, serial)
    slave_serial = slave.zone_wait(zone, serial-1)

    return slave_serial == master_serial


t.start()

ixfr = test(ixfr_master, ixfr_slave, zone)
axfr = test(axfr_master, axfr_slave, zone)

if ixfr or axfr:
    if ixfr and axfr:
        msg = "IXFR and AXFR"
    elif ixfr:
        msg = "IXFR"
    else:
        msg = "AXFR"
    msg = "{} semantic check failed".format(msg)
    dnstest.utils.set_err(msg)



t.end()