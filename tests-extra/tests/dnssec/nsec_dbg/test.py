#!/usr/bin/env python3

from dnstest.test import Test
from dnstest.keys import Keymgr

t = Test()

master = t.server("knot")
slave = t.server("knot")
slave2 = t.server("knot")
zone = t.zone("dk.", storage=".")

t.link(zone, master, slave, ddns=True)
t.link(zone, slave, slave2)

slave.dnssec(zone).enable = True
slave.dnssec(zone).nsec3 = True
slave.dnssec(zone).nsec3_opt_out = True
slave.dnssec(zone).nsec3_iters = 17

slave.zonefile_sync = "-1"
for z in slave.zones:
    slave.zones[z].journal_content = "all"

slave.gen_confile()
_, out, _ = Keymgr.run_check(slave.confile, "dk.", "nsec3-salt", "9729B7160513B7A5")

t.start()

slave.zone_wait(zone)

up = master.update(zone)

up.add("dk.", "86400", "SOA", "b.nic. tech.dk-hostmaster. 1666666666 600 300 1814400 7200")
up.delete("dk.", "TXT")
up.add("dk.", "86400", "TXT", "DK zone update" "Epoch 1553009041" "localtime Tue Mar 19 16:24:01 2019" "gmtime Tue Mar 19 15:24:01 2019"
)

up.delete("nextlevelinlife.dk.", "NS")
up.delete("nextlevelinlife.dk.", "DS")
up.delete("nextlevelinlife.dk.", "TXT")

up.add("nextlevelinlife.dk.", "86400", "NS", "ns1.unoeuro.com.")
up.add("nextlevelinlife.dk.", "86400", "NS", "ns4.unoeuro.com.")
up.add("nextlevelinlife.dk.", "86400", "NS", "ns3.unoeuro.com.")
up.add("nextlevelinlife.dk.", "86400", "NS", "ns2.unoeuro.com.")

up.send("NOERROR")

slave2.zone_wait(zone, serial=1666666665)
slave.ctl("-f zone-flush dk.")
slave2.ctl("-f zone-flush dk.")
t.sleep(2)
slave2.zone_verify(zone)

t.end()
