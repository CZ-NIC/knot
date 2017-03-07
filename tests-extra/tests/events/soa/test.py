#!/usr/bin/env python3

'''Test for SOA events and planning thereof without NOTIFY'''

from dnstest.utils import *
from dnstest.test import Test
import dns.rcode
import random

EXPIRE_SLEEP = 15
RECHECK_SLEEP = 0.5

def test_ok(slave):
    resp = slave.dig("example.", "SOA")
    resp.check(rcode="NOERROR")
    t.sleep(EXPIRE_SLEEP)
    resp = slave.dig("example.", "SOA")
    if resp.resp.rcode() == dns.rcode.SERVFAIL:
        t.sleep(RECHECK_SLEEP)
        # retry if we hit the query just in the middle of AXFR
        resp = slave.dig("example.", "SOA")
    resp.check(rcode="NOERROR")

def test_expired(slave):
    resp = slave.dig("example.", "SOA")
    resp.check(rcode="SERVFAIL")

def create_servers(t, count, zone):
    servers = []
    for _ in range(count):
        master = t.server("bind")
        master.disable_notify = True

        slave = t.server("knot")
        slave.tcp_reply_timeout = "1"

        t.link(zone, master, slave)

        servers.append((master, slave))

    return servers

def init_servers(master, slave):
    master.stop()
    slave.stop()
    master.clean(zone=False)
    slave.clean()
    master.start()
    slave.start()
    slave.zone_wait(zone)

def test_run_case(t, master, slave, action):
    #test that zone does not expire when master is alive
    action(t, slave) # action should keep the event intact
    detail_log("Master alive")
    test_ok(slave)
    master.stop()
    #test that zone does expire when master is down
    detail_log("Expired after master down")
    t.sleep(EXPIRE_SLEEP)
    test_expired(slave)
    #test that expired zone does not change the state after event
    detail_log("Load expired")
    action(t, slave) # action should keep the event intact
    test_expired(slave)

def test_run(t, servers, zone, action):
    master, slave = servers

    check_log("ZONE SOA TIMERS: REFRESH = 1, RETRY = 1, EXPIRE = 10")
    init_servers(master, slave)
    test_run_case(t, master, slave, action)

    check_log("ZONE SOA TIMERS: REFRESH = 20, RETRY = 1, EXPIRE = 10")
    master.update_zonefile(zone, version=1)
    init_servers(master, slave)
    test_run_case(t, master, slave, action)

    check_log("ZONE SOA TIMERS: REFRESH = 1, RETRY = 20, EXPIRE = 10")
    master.update_zonefile(zone, version=2)
    init_servers(master, slave)
    test_run_case(t, master, slave, action)

def reload_server(t, s):
    s.reload()
    t.sleep(1)

def restart_server(t, s):
    s.stop()
    s.start()

t = Test()

zone = t.zone("example.", storage=".")
servers = create_servers(t, 2, zone)

t.start()

check_log("/// ACTION RELOAD ///")
test_run(t, servers[0], zone, reload_server)
check_log("/// ACTION RESTART ///")
test_run(t, servers[1], zone, restart_server)

t.stop()
