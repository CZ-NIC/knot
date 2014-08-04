#!/usr/bin/env python3

'''Test for flush event'''

from dnstest.utils import *
from dnstest.test import Test
import os

FLUSH_SLEEP = 5.5

t = Test()

master = t.server("bind")
slave = t.server("knot")
slave.zonefile_sync = "5s"

zone = t.zone("example.")
zone_path = slave.dir + "/slave/" + zone[0].file_name

t.link(zone, master, slave)
t.start()
slave.stop()
try:
	os.remove(zone_path)
except:
	pass
slave.start()
slave.zone_wait(zone)

#check that the zone file has not been flushed
if os.path.exists(zone_path):
    check_log("Zonefile created too soon: " + str(os.stat(zone_path).st_ctime))
    set_err("SOON FLUSH")

t.sleep(FLUSH_SLEEP) #point of first flush ~ 5s
#check that the zone file has been flushed
if not os.path.exists(zone_path):
    check_log("Zonefile not created")
    set_err("NOT FLUSHED")

prev_mtime = os.stat(zone_path).st_mtime

master.update_zonefile(zone, random=True)
master.reload()
t.sleep(FLUSH_SLEEP) #point of second flush ~ 10s

last_mtime = os.stat(zone_path).st_mtime

#check that the zone file has been flushed after transfer
if prev_mtime == last_mtime:
    check_log("Did not flush after transfer")
    set_err("NO POST-TRANSFER FLUSH")

#set the zonefile-sync parameter to 60s and update master - should not flush
slave.zonefile_sync = "60s"
slave.gen_confile()
slave.reload()
t.sleep(FLUSH_SLEEP) # ~ 15s wait for master to start
master.update_zonefile(zone, random=True)
master.reload()
t.sleep(FLUSH_SLEEP) # ~ 20s

if os.stat(zone_path).st_mtime != last_mtime:
    check_log("Flushed too soon: " + str(os.stat(zone_path).st_mtime) + " vs. " +  str(last_mtime))
    set_err("SOON POST-RELOAD FLUSH")

#set the zonefile-sync parameter to 1s - should flush
slave.zonefile_sync = "1s"
slave.gen_confile()
slave.reload()
t.sleep(1)

if os.stat(zone_path).st_mtime == last_mtime:
    check_log("Did not flush after config change")
    set_err("NO POST-CHANGE FLUSH")

# ~ 31s

t.stop()

