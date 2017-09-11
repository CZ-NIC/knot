#!/usr/bin/env python3

'''Test for signing on a slave Knot w/o zonefile and journal'''

import shutil
from dnstest.utils import *
from dnstest.test import Test

t = Test()

master = t.server("knot")
slave = t.server("knot")
slave.zonefile_sync = "-1"
zone = t.zone_rnd(1, dnssec=False)
t.link(zone, master, slave)
slave.dnssec(zone).enable = True

t.start()

slave.zone_wait(zone)
soa1 = slave.dig(zone[0].name, "SOA", dnssec=True, bufsize=4096)
soa1serial = str(soa1.resp.answer[0].to_rdataset()).split()[5]
detail_log("soa1serial "+soa1serial)
soa1rrsig_expire = str(soa1.resp.answer[1].to_rdataset()).split()[7]
detail_log("soa1rrsig_exp "+soa1rrsig_expire)

slave.stop()
try:
    shutil.rmtree(os.path.join(slave.dir, "timers"))
    shutil.rmtree(os.path.join(slave.dir, "journal"))
except:
    pass
slave.start()

slave.zone_wait(zone)
soa2 = slave.dig(zone[0].name, "SOA", dnssec=True, bufsize=4096)
soa2serial = str(soa2.resp.answer[0].to_rdataset()).split()[5]
detail_log("soa2serial "+soa2serial)
soa2rrsig_expire = str(soa2.resp.answer[1].to_rdataset()).split()[7]
detail_log("soa2rrsig_exp "+soa2rrsig_expire)

if soa2rrsig_expire == soa1rrsig_expire:
    set_err("Zone not resigned, test error")

if soa2serial == soa1serial:
    set_err("Serial not incremented on AXFR")

up = master.update(zone)
up.add("hahahahahah", 3600, "A", "1.2.3.4")
up.send()
t.sleep(9)

msoa3 = master.dig(zone[0].name, "SOA", dnssec=False)
msoa3serial = str(msoa3.resp.answer[0].to_rdataset()).split()[5]
detail_log("msoa3serial "+msoa3serial)

soa4 = slave.dig(zone[0].name, "SOA", dnssec=True, bufsize=4096)
soa4serial = str(soa4.resp.answer[0].to_rdataset()).split()[5]
detail_log("soa4serial "+soa4serial)

if msoa3serial != soa2serial:
    set_err("Serial incremented unexpectedly, test error")

if soa4serial == soa2serial:
    set_err("Serial not incremented on IXFR")

t.end()
