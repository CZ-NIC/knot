#!/usr/bin/env python3

'''Test for DDNS forwarding'''

from dnstest.keys import Tsig
from dnstest.libknot import libknot
from dnstest.test import Test
from dnstest.utils import *

def send_update(master, slave, zone, rcode="NOERROR", slave_tsig_test=None):
    send_update.counter += 1
    owner = "forwarded."
    if rcode != "NOTZONE":
        owner += zone[0].name
    data = "forwarded" + str(send_update.counter)

    if slave_tsig_test:
        slave.tsig_test = slave_tsig_test # Override the key for client DDNS
    update = slave.update(zone)
    if slave_tsig_test:
        slave.tsig_test = None # Don't use the key for the following queries.
    update.add(owner, 1, "TXT", data)
    update.send(rcode)

    resp = master.dig(owner, "TXT")
    if rcode == "NOTAUTH":
        resp.check(rcode="NOERROR", nordata=data)
    elif rcode == "NOERROR":
        resp.check(rcode="NOERROR", rdata=data)
        send_update.serial = slave.zones_wait(zone, send_update.serial)
    elif rcode == "NOTZONE":
        resp.check(rcode="REFUSED")
        t.sleep(3)
    else:
        set_err("ASSERT")

    if rcode != "NOTAUTH":
        t.xfr_diff(master, slave, zone)

tsig_log_history = dict()

def check_log_tsig(server, tsig_name, expect_diff, msg):
    last_count = 0 if tsig_name not in tsig_log_history else tsig_log_history[tsig_name]
    count = server.log_search_count("key " + tsig_name + ".")
    compare(count, last_count + expect_diff, msg)
    tsig_log_history[tsig_name] = count

send_update.counter = 0
send_update.serial = 0

ctl = libknot.control.KnotCtl()

t = Test(tsig=False, stress=False, address=4) # IPv4 allows different loopback addresses

master = t.server("knot", address="127.0.0.2", via=True)
slave = t.server("knot", address="127.0.0.1", via=True) # use the default loopback address so that master's ACL for client queries applies to those forwarded through slave
zone = t.zone("example.com.")

t.link(zone, master, slave, ddns=True)

t.start()

key_master = Tsig("key_master", "hmac-sha256", "abcd")
key_client = Tsig("key_client", "hmac-sha256", "efgh")

master.zones_wait(zone)
send_update.serial = slave.zones_wait(zone)

## client key: None, slave key: None, master key: None

send_update(master, slave, zone)
send_update(master, slave, zone, rcode="NOTZONE")
send_update(master, slave, zone, rcode="NOTAUTH", slave_tsig_test=key_master)

## client key: None, slave key: key_master, master key: key_master

master.tsig = key_master
slave.tsig = key_master

master.gen_confile()
master.reload()
slave.gen_confile()
slave.reload()

# Check that master TSIG hasn't been used so far, except of failed attempt with no TSIG configured.
check_log_tsig(master, "key_master", 1, "Used key_master 0")

send_update(master, slave, zone)
send_update(master, slave, zone, rcode="NOTZONE")

# Check that master TSIG has been used for DDNS+NOTIFY+REFRESH(4)+DDNS+DDNS_ERR.
check_log_tsig(master, "key_master", 8, "Used key_master 1")

## client key: key_master, slave key: key_master, master key: key_master

slave.tsig_test = key_master

slave.gen_confile()
slave.reload()

send_update(master, slave, zone)
send_update(master, slave, zone, rcode="NOTZONE")

## client key: key_client, slave key: key_master, master key: key_client

master.tsig_test = key_client
slave.tsig_test = None

master.gen_confile()
slave.gen_confile()
master.reload()
slave.reload()

# Check that client TSIG hasn't been used so far.
check_log_tsig(master, "key_client", 0, "Used key_client 0")

send_update(master, slave, zone, slave_tsig_test=key_client)
send_update(master, slave, zone, slave_tsig_test=key_client, rcode="NOTZONE")

# Check that client TSIG has been used for DDNS+AXFR(3)+DDNS+DDNS_ERR+AXFR(3).
check_log_tsig(master, "key_client", 9, "Used key_client 1")

## client key: key_client, slave key: key_client, key_master, master key: key_master

slave.tsig_test = key_client

master.gen_confile()
slave.gen_confile()
master.reload()
slave.reload()

# Get reference value.
check_log_tsig(master, "key_master", 13, "Used key_master 2")

send_update(master, slave, zone)
send_update(master, slave, zone, rcode="NOTZONE")
send_update(master, slave, zone, rcode="NOTAUTH", slave_tsig_test=key_master)

# Check that client TSIG has been used for AXFR(3)+AXFR(3).
check_log_tsig(master, "key_client", 6, "Used key_client 2")

# Check that master TSIG has been used for 4xACL and NOTIFY+2xIXFR+DDNS to slave.
check_log_tsig(master, "key_master", 8, "Used key_master 3")

t.end()
