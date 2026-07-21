#!/usr/bin/env python3

'''Test for reload of a changed zone (serial up, nochange, serial down). '''

from dnstest.test import Test
from dnstest.utils import *

t = Test()

master = t.server("bind")
slave = t.server("knot")
sub = t.server("knot")

zone = t.zone("example.com.", storage=".")
t.link(zone, master, slave)
t.link(zone, slave, sub)

slave.conf_zone(zone).zonefile_sync = 0

# Load newer zone to the slave
slave.update_zonefile(zone, version="slave")

zfpath = slave.zones[zone[0].name].zfile.path
mtime0 = os.stat(zfpath).st_mtime

t.start()

serial_master = master.zone_wait(zone)
serial_slave = slave.zone_wait(zone)

# Check that the slave's serial is larger than master's
assert serial_master <= serial_slave

# Retransfer zone with lower serial
slave.ctl("zone-retransfer example.com.", wait=True)
t.sleep(2) # allow zone file update

serial_slave = slave.zone_wait(zone)
compare(serial_slave, serial_master, "Serial after retransfer")

mtime1 = os.stat(zfpath).st_mtime
if mtime1 == mtime0:
    set_err("Not flushed after retransfer")

# Retransfer zone with the same serial
master.update_zonefile(zone, version="master")
master.reload()

slave.ctl("zone-retransfer example.com.", wait=True)
sub.ctl("zone-retransfer example.com.", wait=True)
t.sleep(1) # allow zone file update

resp = sub.dig("diff.example.com", "A")
resp.check(rcode="NOERROR")

mtime2 = os.stat(zfpath).st_mtime
if mtime2 == mtime1:
    set_err("Not flushed after retransfer")

# Retransfer with fixfr, incrementing serial on slave
slave.ctl("zone-retransfer +fixfr example.com.", wait=True)
serial_master = master.zone_wait(zone)
serial_lowest = serial_master
serial_slave = sub.zone_wait(zone, serial_master)

# Inrement on master, slave still one ahead
master.update_zonefile(zone, version="slave")
master.reload()
slave.ctl("zone-retransfer +fixfr example.com.", wait=True)
serial_master = master.zone_wait(zone, serial_master)
serial_slave = sub.zone_wait(zone, serial_master)
resp = slave.dig("new.example.com", "A")
resp.check(rcode="NOERROR")

t.xfr_diff(slave, sub, zone, { zone[0].name: serial_lowest }) # IXFR diff

t.end()
