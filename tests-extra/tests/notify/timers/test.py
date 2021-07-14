#!/usr/bin/env python3

'''Test for NOTIFY in zone timers'''

from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")

zone = t.zone("notify.", storage=".")

t.link(zone, master, slave)

BACKUP_DIR = slave.dir + "/backup"

t.start()

serial = master.zone_wait(zone)
slave.zone_wait(zone)

slave.ctl("zone-backup +backupdir " + BACKUP_DIR, wait=True)

# temporarily disable notify
slave.disable_notify = True
master.gen_confile()
master.reload()

master.update_zonefile(zone, version=1)
master.ctl("zone-reload", wait=True)
master.stop()

resp = slave.dig("notify.", "SOA")
resp.check_soa_serial(serial)

# enable notify again
slave.disable_notify = False
master.gen_confile()
master.start()

slave.zone_wait(zone, serial) # started master notifies slave with new serial

slave.ctl("zone-restore +backupdir " + BACKUP_DIR, wait=True)
t.sleep(2)
resp = slave.dig("notify.", "SOA")
resp.check_soa_serial(serial)

master.stop()
master.start() # master remembers that it have sent notify and doesn't re-send
master.zone_wait(zone, serial)
t.sleep(4)

resp = slave.dig("notify.", "SOA")
resp.check_soa_serial(serial) # slave keeps older SOA

t.end()
