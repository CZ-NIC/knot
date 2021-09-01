#!/usr/bin/env python3

'''Test of zone validation'''

from dnstest.test import Test
import dnstest.utils

t = Test()

master = t.server("knot")
slave = t.server("knot")

zones_ok = t.zone("ok.nsec.", storage=".")
zones_ok3 = t.zone("ok.nsec3.", storage=".") + t.zone("ok.2nsec3.", storage=".")
zones_nok = t.zone("missing.nsec.", storage=".") + t.zone("bitmap.nsec.", storage=".") + \
            t.zone("chain.nsec.", storage=".") + t.zone("rrsig.a.", storage=".") + \
            t.zone("rrsig.nsec.", storage=".") + t.zone("redundant.invalid.rrsig.", storage=".")
zones_nok3 = t.zone("missing.nsec3", storage=".") + t.zone("bitmap.nsec3.", storage=".") + \
             t.zone("chain.nsec3.", storage=".") + t.zone("rrsig.nsec3", storage=".") + \
             t.zone("optout.ent.", storage=".")
zones_unsigned = t.zone("example.com.")

zones = zones_ok + zones_ok3 + zones_nok + zones_nok3
t.link(zones + zones_unsigned, master, slave, ixfr=True)

for z in zones_ok + zones_nok:
    slave.dnssec(z).validate = True
for z in zones_ok3 + zones_nok3:
    slave.dnssec(z).validate = True
for z in zones_unsigned:
    slave.dnssec(z).validate = True

t.start()

serials_ok = master.zones_wait(zones_ok + zones_ok3)
serials_all = master.zones_wait(zones)
slave.zones_wait(zones)

for z in zones_unsigned:
    servfail = slave.dig(z.name, "SOA")
    servfail.check(rcode="SERVFAIL")

for z in zones:
    master.update_zonefile(z, version=2)

master.ctl("zone-reload")

master.zones_wait(zones, serials=serials_all)
slave.zones_wait(zones_ok + zones_ok3, serials=serials_ok)
t.sleep(5) # make sure all the IXFR attempts take place

for z in zones_nok + zones_nok3:
    mresp = master.dig(z.name, "SOA")
    sresp = slave.dig(z.name, "SOA")
    if mresp.soa_serial() == sresp.soa_serial():
        dnstest.utils.set_err("NOK ZONE %s ACCEPTED" % z.name)

slave.ctl("zone-retransfer") # force AXFR
t.sleep(7)

for z in zones_nok + zones_nok3:
    mresp = master.dig(z.name, "SOA")
    sresp = slave.dig(z.name, "SOA")
    if mresp.soa_serial() == sresp.soa_serial():
        dnstest.utils.set_err("NOK ZONE %s ACCEPTED" % z.name)

t.end()
