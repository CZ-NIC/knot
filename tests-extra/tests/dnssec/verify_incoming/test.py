#!/usr/bin/env python3

'''Check that Knot validates RRSIGs incoming thru IXFR'''

from dnstest.utils import *
from dnstest.test import Test

def ans_len(resp):
    ret = 0
    for rrset in resp.resp.answer:
        ret = ret + len(rrset.to_rdataset())
    return ret

def check_rrsig(slave, nordata, msg):
    resp = slave.dig("node.example.com.", "RRSIG")

    if ans_len(resp) != 1:
        print(msg + ": two RRSIGs")
        set_err(msg + ": two RRSIGs")

    for ansrrset in resp.resp.answer:
        for ansrr in ansrrset.to_rdataset():
            rrsig = ansrr.to_text()
            if rrsig == nordata:
                print(msg + ": invalid RRSIG")
                set_err(msg + ": invalid RRSIG")

    resp = slave.dig("nodf.example.com.", "RRSIG")

    if len(resp.resp.answer) != 0:
        print(msg + ": invalid node RRSIG")
        set_err(msg + ": invalid node RRSIG")

    resp = slave.dig("mail.example.com.", "RRSIG")

    if ans_len(resp) != 1:
        print(msg + ": two RRSIGs for unchanged")
        set_err(msg + ": two RRSIGs for unchanged")


t = Test()

# Create master and slave servers
knot_master = t.server("knot")
knot_slave1 = t.server("knot")

zone = t.zone("example.com.", storage=".")

t.link(zone, knot_master, knot_slave1, ddns=True, ixfr=True)

# Enable autosigning on slave
knot_slave1.dnssec(zone).enable = True
knot_slave1.dnssec(zone).nsec3 = True # to avoid NSEC-RRSIGs in zone nodes

t.start()
serial = knot_slave1.zone_wait(zone)

resp = knot_slave1.dig("node.example.com.", "RRSIG")
rrsig1 = resp.resp.answer[0].to_rdataset()[0].to_text()

knot_master.zones["example.com."].zfile.update_soa()
with open(knot_master.zones["example.com."].zfile.path, "a") as zf:
    zf.write('node.example.com. 3600 A 100.0.0.2\n')

knot_master.ctl("zone-reload")
serial = knot_slave1.zone_wait(zone, serial)

# rrsig1 is no longer valid
check_rrsig(knot_slave1, rrsig1, "Initial check")

# try promoting rrsig1 through IXFR
knot_master.zones["example.com."].zfile.update_soa()
with open(knot_master.zones["example.com."].zfile.path, "a") as zf:
    zf.write('node.example.com. 3600 A 100.0.0.3\n')
    zf.write('node.example.com. 3600 RRSIG ' + rrsig1 + '\n')    # invalid rrsig for existing rrset
    zf.write('mail.example.com. 3600 RRSIG ' + rrsig1 + '\n')    # invalid rrsig for unchanged rrset
    zf.write('node.example.com. 3600 RRSIG AAA' + rrsig1 + '\n') # rrsig for nonexisting rrset
    zf.write('nodf.example.com. 3600 RRSIG ' + rrsig1 + '\n')    # rrsig for nonexisting node

knot_master.ctl("zone-reload")
serial = knot_slave1.zone_wait(zone, serial)

check_rrsig(knot_slave1, rrsig1, "After IXFR")

knot_slave1.ctl("zone-retransfer", wait=True)
t.sleep(4)

check_rrsig(knot_slave1, rrsig1, "After AXFR")

t.end()
