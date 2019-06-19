#!/usr/bin/env python3

'''Test for automatic DNSSEC signing on a slave Knot'''

from dnstest.utils import *
from dnstest.test import Test

serial = 2010111213
addr = "192.0.0.42"

def test_update(master, slave, zone):
    #Slave zone diverges from master by re-signing
    for i in range(2):
        t.sleep(2)
        slave.ctl("zone-sign example.com.")

    #Master zone receives an update
    update = master.update(zone)
    update.add("new.example.com.", 3600, "A", addr)
    update.send("NOERROR")

    #Wait until slave receives update and sets correct SOA
    slave.zone_wait(zone, serial+3, equal=True)

    #Check that slave was updated and the new entry is signed
    response = slave.dig("new.example.com.", "A");
    response.check(rcode="NOERROR", rdata=addr);
    response = slave.dig("new.example.com.", "RRSIG");
    #Should get a RRSIG for the new A record and the new NSEC record
    response.check_count(2)

    slave.zone_backup(zone, flush=True)
    slave.zone_verify(zone)

t = Test()

# Create master and slave servers
bind_master = t.server("bind")
knot_master = t.server("knot")
knot_slave1 = t.server("knot")
knot_slave2 = t.server("knot")

zone = t.zone("example.com.", storage=".")

t.link(zone, bind_master, knot_slave1, ddns=True)
t.link(zone, knot_master, knot_slave2, ddns=True)

# Enable autosigning on slave
knot_slave1.dnssec(zone).enable = True
knot_slave2.dnssec(zone).enable = True

t.start()

test_update(bind_master, knot_slave1, zone)
test_update(knot_master, knot_slave2, zone)

t.end()
