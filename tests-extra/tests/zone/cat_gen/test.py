#!/usr/bin/env python3

'''Test of Catalog zone generation.'''

from dnstest.test import Test
from dnstest.utils import set_err, detail_log

t = Test()

master = t.server("knot")
slave = t.server("knot")

catz = t.zone("example.")
zone = t.zone("example.com.")

t.link(catz, master, slave)
t.link(zone, master)

for z in zone:
    master.zones[z.name].catalog_gen_link(master.zones[catz[0].name])

slave.zones[catz[0].name].catalog = True
slave.dnssec(catz[0]).enable = True
slave.dnssec(catz[0]).single_type_signing = True

t.start()

# testcatse 1: initial catalog zone with 1 member
slave.zones_wait(zone)

# testcase 2: adding member zones online
zone_add = t.zone("flags.") + t.zone("records.")
t.link(zone_add, master)
for z in zone_add:
    master.zones[z.name].catalog_gen_link(master.zones[catz[0].name])

master.gen_confile()
master.reload()

slave.zones_wait(zone + zone_add)

# testcase 3: removing member zone offline
serial_bef_rem = slave.zone_wait(catz, udp=False, tsig=True)
master.stop()
master.zones.pop("example.com.")
master.gen_confile()
master.start()
slave.zone_wait(catz, serial_bef_rem, udp=False, tsig=True)
resp = slave.dig("example.com.", "SOA")
resp.check(rcode="REFUSED")

#testcase 4: remove/add same member zone while slave offline, with purge
resp0 = slave.dig("records.", "DNSKEY")
resp0.check_count(1, "DNSKEY")
dnskey0 = resp0.resp.answer[0].to_rdataset()
slave.stop()

temp_rem = master.zones.pop("records.")
master.gen_confile()
master.reload()
t.sleep(7)
master.ctl("-f zone-purge +orphan records.")
master.zones["records."] = temp_rem
master.gen_confile()
master.reload()

slave.start()
slave.ctl("zone-refresh")
t.sleep(7)
resp1 = slave.dig("records.", "DNSKEY")
resp1.check_count(1, "DNSKEY")
dnskey1 = resp1.resp.answer[0].to_rdataset()
if dnskey0 == dnskey1:
    set_err("ZONE NOT PURGED")

t.end()
