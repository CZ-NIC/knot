#!/usr/bin/env python3

'''Test for SOA events and planning thereof'''

from dnstest.test import Test
import random

EXPIRE_SLEEP = 20
RESYNC_SLEEP = 10

def restart_server(s):
    s.stop()
    s.start()

def remove_zone(server, zone):
    if zone.name in server.zones:
        server.zones.pop(zone.name)

def make_master(server, zone):
    remove_zone(server, zone)
    server.set_master(zone)
    server.gen_confile()

def make_slave(server, zone, master):
    remove_zone(server, zone)
    server.set_slave(zone, master)
    server.gen_confile()

def test_expired(zone, server):
    resp = server.dig(zone.name, "SOA")
    resp.check(rcode="SERVFAIL")

def test_alive(zone, server):
    server.zone_wait(zone)

def expire_tests(t, zone, master, slave):
    # Stop the master and let the zone expire.
    master.stop()
    t.sleep(EXPIRE_SLEEP)
    test_expired(zone, slave)

    # Reload shoudn't affect.
    slave.reload()
    test_expired(zone, slave)

    # Restart shoudn't affect.
    restart_server(slave)
    test_expired(zone, slave)

    # Make the server master, zone should appear.
    make_master(slave, zone)
    slave.reload()
    test_alive(zone, slave)

    # Make it slave again, return to initial state.
    make_slave(slave, zone, master)
    master.start()
    slave.reload()
    t.sleep(RESYNC_SLEEP)

    # Let the zone expire while the server is down.
    slave.stop()
    master.stop()
    t.sleep(EXPIRE_SLEEP)
    slave.start()
    test_expired(zone, slave)

    # Reload shoudn't affect.
    slave.reload()
    test_expired(zone, slave)

    # Restart shoudn't affect.
    restart_server(slave)
    test_expired(zone, slave)

    # Start master, wait for next bootstrap.
    master.start()
    test_alive(zone, slave) # may take about a minute

def refresh_tests(t, zone, master, slave):
    # Set long refresh interval
    master.zones[zone.name].zfile.update_soa(serial=2, refresh=1200, retry=1200, expire=3600)
    master.reload()
    slave.zone_wait(zone, 2, equal=True)

    # Bump serial
    master.zones[zone.name].zfile.update_soa(serial=3, refresh=1, retry=1, expire=15)
    master.reload()

    # Restart and reload shoudn't cause refresh
    restart_server(slave)
    slave.reload()
    slave.ctl("zone-reload %s" % zone.name)
    slave.zone_wait(zone, 2, equal=True)

    # Force refresh should work
    slave.ctl("zone-refresh %s" % zone.name)
    slave.zone_wait(zone, 3, equal=True)

t = Test()

# this zone has refresh = 1s, retry = 1s and expire = 15s
[zone] = t.zone("example.", storage=".")

master = t.server("knot")
slave = t.server("knot")

for server in [master, slave]:
    server.disable_notify = True
    server.tcp_reply_timeout = "1s"

t.link([zone], master, slave)

t.start()

master.zone_wait(zone)
slave.zone_wait(zone)

expire_tests(t, zone, master, slave)
refresh_tests(t, zone, master, slave)

t.stop()
