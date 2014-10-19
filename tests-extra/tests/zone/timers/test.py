#!/usr/bin/env python3

'''Test for SOA events and planning thereof'''

from dnstest.test import Test
import random

EXPIRE_SLEEP = 17
RETRY_SLEEP = 10
START_SLEEP = 5

def restart_server(s):
    s.stop()
    s.start()

def set_master(t, master, slave, zone):
    t.link(zone, master)

def set_slave(t, master, slave, zone):
    t.link(zone, master, slave)

def role_switch(t, master, slave, zone, action):
    slave.zones = {}
    master.zones = {}
    slave.max_conn_idle = "1s"
    master.max_conn_idle = "1s"
    action(t, master, slave, zone)
    t.generate_conf()

def test_expire(zone, server):
    resp = server.dig("example.", "SOA")
    resp.check(rcode="SERVFAIL")    

def test_alive(zone, server):
    server.zone_wait(zone)

def expire_tests(t, zone, master, slave):
    # There are 3 ways for zone to expire:
    #  - zone expires while server is alive
    #  - zone expire is planned before server restart and occurs when the server is alive again
    #  - zone expires while server is down

    # Stop the master and let the zone expire (alive expire).
    master.stop()
    t.sleep(EXPIRE_SLEEP)

    # Restart and make sure the zone is not served.
    restart_server(slave)
    test_expire(zone, slave)

    # Switch slave to master and check that the zone is alive again.
    role_switch(t, slave, master, zone, set_master)
    restart_server(slave)
    test_alive(zone, slave)

    # Switch roles back - state of servers same as the beginning of the test.
    role_switch(t, master, slave, zone, set_slave)
    restart_server(slave)
    master.start()
    master.zone_wait(zone)
    slave.zone_wait(zone)

    # Stop the master, let refresh fail (= expire planned) then restart the slave and wait for expire.
    master.stop()
    t.sleep(EXPIRE_SLEEP // 2)
    restart_server(slave) 
    t.sleep((EXPIRE_SLEEP // 2) + 1 - START_SLEEP)
    test_expire(zone, slave)

    # Start the master and wait for sync with slave.
    master.start()
    slave.zone_wait(zone)

    # Stop both servers.
    master.stop()
    slave.stop()

    # Let the zone expire while servers are down.
    t.sleep(EXPIRE_SLEEP * 2)
    slave.start()
    test_expire(zone, slave)

def refresh_tests(t, zone, master, slave):
    # Replace the SOA - set higher retry.
    master.zones[zone[0].name].zfile.update_soa(serial=2, refresh=1, retry=20, expire=10)
    master.start()
    slave.zone_wait(zone, 1)

    # Stop the master.
    master.stop()
    # Wait for refresh to fail - expire will be planned in ~12s on the slave.
    t.sleep(2) 
    # Restart the slave - there should be no refresh on startup.
    restart_server(slave) # comes with START_SLEEP sleep.
    # Start the master again.
    master.start() # comes with START_SLEEP sleep.
    t.sleep(2)
    # Zone should be expired by now, ~8s to refresh retry.
    test_expire(zone, slave)

    t.sleep(10)
    # Zone should be loaded again once refresh timer triggers the event.
    test_alive(zone, slave)

t = Test()

# this zone has refresh = 1s, retry = 1s and expire = 1s + 2s for connection timeouts
zone = t.zone("example.", storage=".")

master = t.server("knot")
master.disable_notify = True
master.max_conn_idle = "1s"

slave = t.server("knot")
slave.disable_notify = True
slave.max_conn_idle = "1s"

t.link(zone, master, slave)

t.start()

master.zone_wait(zone)
slave.zone_wait(zone)

expire_tests(t, zone, master, slave)
refresh_tests(t, zone, master, slave)

t.stop()

