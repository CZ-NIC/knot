#!/usr/bin/env python3

'''Test of catalog recover from kill between update and zonedb_reload.'''

from dnstest.test import Test
from dnstest.utils import set_err, detail_log

t = Test(address=4, stress=False)

stuck_parent = t.server("dummy", address="8.8.8.8", port="23") # this address/port shall time out
master = t.server("knot")

catz = t.zone("catalog.")
stuckzone = t.zone("records.")

t.link(catz + stuckzone, master)

master.cat_interpret(catz)

master.zones[catz[0].name].journal_content = "all"

master.dnssec(stuckzone).enable = True
master.dnssec(stuckzone).single_type_signing = True
master.dnssec(stuckzone).ds_push = stuck_parent
master.dnssec(stuckzone).propagation_delay = 1
master.tcp_remote_io_timeout = 40000

master.gen_confile()
master.key_gen(stuckzone[0].name, ksk="true", zsk="true", active="+0")

t.start()

serial = master.zone_wait(catz, udp=False, tsig=True)

master.key_gen(stuckzone[0].name, ksk="true", zsk="true", ready="+0", active="+100")
master.ctl("zone-sign")
t.sleep(4)

resp = master.dig("example.", "SOA")
resp.check(rcode="SERVFAIL")

up = master.update(catz)
up.add("add.zones.%s" % catz[0].name, 3600, "PTR", "added.")
up.send()

master.zone_wait(catz, serial, udp=False, tsig=True)

resp = master.dig("added.", "SOA")
resp.check(rcode="REFUSED")

master.kill() # zonedb_reload does not make it before the kill because one BG worker is stuck on DS push

t.sleep(5)

master.start()
master.zone_wait(catz, udp=False, tsig=True)
t.sleep(4)

resp = master.dig("added.", "SOA")
resp.check(rcode="SERVFAIL") # not REFUSED

t.end()
