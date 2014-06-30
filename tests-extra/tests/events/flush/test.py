#!/usr/bin/env python3

'''Test for flush event'''

from dnstest.utils import *
from dnstest.test import Test
import os

FLUSH_SLEEP = 5

t = Test()

master = t.server("bind")
slave = t.server("knot")
slave.zonefile_sync = "4s"

zone = t.zone("example.")

t.link(zone, master, slave)
t.start()
slave.zone_wait(zone)

#check that the zone file has not been flushed
zone_path = slave.dir + "/slave/example.zone" 
if os.path.exists(zone_path):
    detail_log("Zonefile created too soon: " + str(os.stat(zone_path).st_ctime))
    set_err("FLUSHED")

t.sleep(FLUSH_SLEEP)
#check that the zone file has been flushed
if not os.path.exists(zone_path):
    detail_log("Zonefile not created")
    set_err("NOT FLUSHED")

prev_mtime = os.stat(zone_path).st_mtime

master.update_zonefile(zone, random=True)
master.reload()
t.sleep(FLUSH_SLEEP)

last_mtime = os.stat(zone_path).st_mtime

#check that the zone file has been flushed after transfer
if prev_mtime == last_mtime:
    detail_log("Did not flush after transfer")
    set_err("POST-TRANSFER FLUSH")

#set the zonefile-sync parameter to 20s and update master - should not flush
slave.zonefile_sync = "20s"
slave.gen_confile()
slave.reload()
master.update_zonefile(zone, random=True)
master.reload()
t.sleep(FLUSH_SLEEP)

if os.stat(zone_path).st_mtime != last_mtime:
    detail_log("Flushed too soon: " + str(os.stat(zone_path).st_mtime) + " vs. " +  str(last_mtime))
    set_err("SOON FLUSH")

#set the zonefile-sync parameter to 1s - should flush
slave.zonefile_sync = "1s"
slave.gen_confile()
slave.reload()

if os.stat(zone_path).st_mtime == last_mtime:
    detail_log("Did not flush after config change")
    set_err("CHANGE FLUSH")

t.stop()

