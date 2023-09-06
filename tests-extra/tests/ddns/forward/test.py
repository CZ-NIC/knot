#!/usr/bin/env python3

'''Test for DDNS forwarding'''

from dnstest.keys import Tsig
from dnstest.libknot import libknot
from dnstest.test import Test
from dnstest.utils import *

def send_update(master, slave, zone, positive=True, slave_tsig_test=None):
    send_update.counter += 1
    owner = "forwarded."
    if positive:
        owner += zone[0].name
    data = "forwarded" + str(send_update.counter)

    if slave_tsig_test:
        slave.tsig_test = slave_tsig_test # Override the key for client DDNS
    update = slave.update(zone)
    if slave_tsig_test:
        slave.tsig_test = None # Don't use the key for the following queries.
    update.add(owner, 1, "TXT", data)
    if positive:
        update.send("NOERROR")
    else:
        # NAME out of zone
        update.send("NOTZONE")

    resp = master.dig(owner, "TXT")
    if positive:
        resp.check(rdata=data)
        send_update.serial = slave.zones_wait(zone, send_update.serial)
    else:
        resp.check(rcode="REFUSED")
        t.sleep(3)

    t.xfr_diff(master, slave, zone)
send_update.counter = 0
send_update.serial = 0

ctl = libknot.control.KnotCtl()

t = Test(tsig=False, stress=False)

master = t.server("knot")
slave = t.server("knot")
zone = t.zone("example.com.")

t.link(zone, master, slave, ddns=True)

t.start()

master.zones_wait(zone)
send_update.serial = slave.zones_wait(zone)

## client key: None, slave key: None, master key: None

send_update(master, slave, zone)
send_update(master, slave, zone, positive=False)

## client key: None, slave key: key_master, master key: key_master

key_master = Tsig("key_master", "hmac-sha256", "abcd")
master.tsig = key_master
slave.tsig = key_master

master.gen_confile()
master.reload()
slave.gen_confile()
slave.reload()

# Check that master TSIG hasn't been used so far.
isset(master.log_search_count("key key_master.") == 0, "No key_master")

send_update(master, slave, zone)
send_update(master, slave, zone, positive=False)

# Check that master TSIG has been used for 2xDDNS and QUERY+XFR to slave.
isset(master.log_search_count("key key_master.") == 4, "Used key_master")

## client key: key_master, slave key: key_master, master key: key_master

slave.tsig_test = key_master

slave.gen_confile()
slave.reload()

send_update(master, slave, zone)
send_update(master, slave, zone, positive=False)

## client key: key_client, slave key: key_master, master key: key_client

key_client = Tsig("key_client", "hmac-sha256", "efgh")
master.tsig_test = key_client
slave.tsig_test = None

master.gen_confile()
slave.gen_confile()
master.reload()
slave.reload()

# Check that client TSIG hasn't been used so far.
isset(master.log_search_count("key key_client.") == 0, "No key_client")

send_update(master, slave, zone, slave_tsig_test=key_client)
send_update(master, slave, zone, slave_tsig_test=key_client, positive=False)

# Check that client TSIG has been used for 2xDDNS and QUERY+XFR to client.
isset(master.log_search_count("key key_client.") == 4, "Used key_client")

t.end()
