#!/usr/bin/env python3

'''Test for NOTIFY retry selectively for failed servers'''

from dnstest.test import Test

t = Test(tsig=True)

master = t.server("knot")
slave1 = t.server("knot")
slave2 = t.server("knot")
slave3 = t.server("knot")

zone = t.zone_rnd(1, records=300)

t.link(zone, master, slave1)
t.link(zone, master, slave2)
t.link(zone, master, slave3)

master.zones[zone[0].name].retry_max = 10

t.start()

serial = master.zone_wait(zone)
slave1.zone_wait(zone)
slave2.zone_wait(zone)
slave3.zone_wait(zone)

# disable notify to slave1 and slave2

master.disable_notify = True
slave1.gen_confile()
slave3.gen_confile()
slave1.reload()
slave3.reload()
t.sleep(3)

master.random_ddns(zone)
master.zone_wait(zone, serial)
slave2.zone_wait(zone, serial)

t.sleep(1)

# check that slave1 and slave2 haven't been notified

slave1.zone_wait(zone, serial, equal=True, greater=False)
slave3.zone_wait(zone, serial, equal=True, greater=False)

# check that slave1 has been re-notified

master.disable_notify = False
slave1.gen_confile()
slave1.reload()

slave1.zone_wait(zone, serial)

# change port on slave3 and check that slave3 has been re-notified upon master restart

slave2.stop()

slave3.port = slave2.port
master.gen_confile()
master.reload()

t.sleep(5)

slave3.gen_confile()
slave3.stop()
slave3.start()

t.sleep(2)

slave3.zone_wait(zone, serial)

t.end()
