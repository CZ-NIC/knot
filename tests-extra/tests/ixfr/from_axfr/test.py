#!/usr/bin/env python3

'''Test for AXFR-style IXFR'''

from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")
sub_slave = t.server("knot")
zone = t.zone("xfr", storage=".")

t.link(zone, master, slave)
t.link(zone, slave, sub_slave)

slave.conf_zone(zone).ixfr_from_axfr = True

t.start()

serial = sub_slave.zones_wait(zone)
serial_init = serial

# update zone with small change
master.update_zonefile(zone, version=1)
master.reload()
master.zones_wait(zone, serial)

# check that master properly sends AXFR-style IXFR
for z in zone:
    t.check_axfr_style_ixfr(master, "xfr", serial[z.name])

sub_slave.zones_wait(zone, serial)

t.xfr_diff(master, slave, zone)
t.xfr_diff(slave, sub_slave, zone, serial_init)

# test case 2: generate+verify ZONEMD

slave.conf_zone(zone).zonemd_generate = "zonemd-sha384"
sub_slave.conf_zone(zone).zonemd_verify = True

slave.gen_confile()
sub_slave.gen_confile()
slave.reload()
sub_slave.reload()

t.sleep(5)
serial = sub_slave.zones_wait(zone)

master.update_zonefile(zone, version=2)
master.reload()
sub_slave.zones_wait(zone, serial)

t.xfr_diff(slave, sub_slave, zone, serial_init)

# test case 3: generate+verify DNSSEC as well

for z in zone:
    slave.dnssec(z).enable = True
    sub_slave.conf_zone(z).dnssec_validation = True

slave.gen_confile()
sub_slave.gen_confile()
slave.reload()
sub_slave.reload()

t.sleep(5)
serial = sub_slave.zones_wait(zone)

master.update_zonefile(zone, version=3)
master.reload()
sub_slave.zones_wait(zone, serial)

t.xfr_diff(slave, sub_slave, zone, serial_init)

t.stop()
