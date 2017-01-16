#!/usr/bin/env python3

'''Manual DDNS testing'''

from dnstest.utils import *
from dnstest.test import Test

t = Test()

def check_soa(master, prev_soa):
    soa_resp = master.dig("ddns.", "SOA")
    compare(prev_soa, soa_resp.resp.answer, "SOA changed when it shouldn't")

def verify(master, zone, dnssec):
    if not dnssec:
        return
    master.flush()
    t.sleep(1)
    master.zone_verify(zone)

def do_normal_tests(master, zone, dnssec=False):
    # add node
    check_log("Node addition")
    up = master.update(zone)
    up.add("rrtest.ddns.", 3600, "A", "1.2.3.4")
    up.send("NOERROR")
    resp = master.dig("rrtest.ddns.", "A")
    resp.check(rcode="NOERROR", rdata="1.2.3.4")
    verify(master, zone, dnssec)

    # add record to existing rrset
    check_log("Node update - new record")
    up = master.update(zone)
    up.add("rrtest.ddns.", 3600, "A", "1.2.3.5")
    up.send("NOERROR")
    resp = master.dig("rrtest.ddns.", "A")
    resp.check(rcode="NOERROR", rdata="1.2.3.4")
    resp.check(rcode="NOERROR", rdata="1.2.3.5")
    verify(master, zone, dnssec)

    # add records to existing rrset
    check_log("Node update - new records")
    up = master.update(zone)
    up.add("rrtest.ddns.", 3600, "A", "1.2.3.7")
    up.add("rrtest.ddns.", 3600, "A", "1.2.3.0")
    up.send("NOERROR")
    resp = master.dig("rrtest.ddns.", "A")
    resp.check(rcode="NOERROR", rdata="1.2.3.0")
    resp.check(rcode="NOERROR", rdata="1.2.3.4")
    resp.check(rcode="NOERROR", rdata="1.2.3.5")
    resp.check(rcode="NOERROR", rdata="1.2.3.7")
    verify(master, zone, dnssec)

    # add rrset to existing node
    check_log("Node update - new rrset")
    up = master.update(zone)
    up.add("rrtest.ddns.", 3600, "TXT", "abcedf")
    up.send("NOERROR")
    resp = master.dig("rrtest.ddns.", "TXT")
    resp.check(rcode="NOERROR", rdata="abcedf")
    resp = master.dig("rrtest.ddns.", "A")
    resp.check(rcode="NOERROR", rdata="1.2.3.0")
    resp.check(rcode="NOERROR", rdata="1.2.3.4")
    resp.check(rcode="NOERROR", rdata="1.2.3.5")
    resp.check(rcode="NOERROR", rdata="1.2.3.7")
    verify(master, zone, dnssec)

    # remove rrset
    check_log("Node update - rrset removal")
    up = master.update(zone)
    up.delete("rrtest.ddns.", "TXT")
    up.send("NOERROR")
    resp = master.dig("rrtest.ddns.", "TXT")
    resp.check(rcode="NOERROR")
    compare(resp.count(section="answer"), 0, "TXT rrset removal")
    resp = master.dig("rrtest.ddns.", "A")
    resp.check(rcode="NOERROR", rdata="1.2.3.0")
    resp.check(rcode="NOERROR", rdata="1.2.3.4")
    resp.check(rcode="NOERROR", rdata="1.2.3.5")
    resp.check(rcode="NOERROR", rdata="1.2.3.7")
    verify(master, zone, dnssec)

    # remove record
    check_log("Node update - record removal")
    up = master.update(zone)
    up.delete("rrtest.ddns.", "A", "1.2.3.5")
    up.send("NOERROR")
    resp = master.dig("rrtest.ddns.", "A")
    resp.check(rcode="NOERROR", nordata="1.2.3.5")
    resp.check(rcode="NOERROR", rdata="1.2.3.0")
    resp.check(rcode="NOERROR", rdata="1.2.3.4")
    resp.check(rcode="NOERROR", rdata="1.2.3.7")
    verify(master, zone, dnssec)

    # remove records
    check_log("Node update - records removal")
    up = master.update(zone)
    up.delete("rrtest.ddns.", "A", "1.2.3.0")
    up.delete("rrtest.ddns.", "A", "1.2.3.7")
    up.send("NOERROR")
    resp = master.dig("rrtest.ddns.", "A")
    resp.check(rcode="NOERROR", nordata="1.2.3.0")
    resp.check(rcode="NOERROR", nordata="1.2.3.7")
    resp.check(rcode="NOERROR", rdata="1.2.3.4")
    verify(master, zone, dnssec)

    # remove node
    check_log("Node removal")
    up = master.update(zone)
    up.delete("rrtest.ddns.", "ANY")
    up.send("NOERROR")
    resp = master.dig("rrtest.ddns.", "A")
    resp.check(rcode="NXDOMAIN")
    verify(master, zone, dnssec)

    # add delegation
    check_log("Delegation addition")
    up = master.update(zone)
    up.add("deleg.ddns.", 3600, "NS", "a.deleg.ddns.")
    up.add("a.deleg.ddns.", 3600, "A", "1.2.3.4")
    up.send("NOERROR")
    resp = master.dig("deleg.ddns.", "NS")
    resp.check_record(section="authority", rtype="NS", rdata="a.deleg.ddns.")
    resp.check_record(section="additional", rtype="A", rdata="1.2.3.4")
    verify(master, zone, dnssec)

    # add CNAME to node with A records, should be ignored
    check_log("Add CNAME to A node")
    up = master.update(zone)
    up.add("dns1.ddns.", "3600", "CNAME", "ignore.me.ddns.")
    up.send("NOERROR")
    resp = master.dig("dns1.ddns.", "CNAME")
    compare(resp.count(), 0, "Added CNAME when it shouldn't")
    verify(master, zone, dnssec)

    # create new node by adding RR + try to add CNAME
    # the update should ignore the CNAME
    check_log("Add new node + add CNAME to it")
    up = master.update(zone)
    up.add("rrtest2.ddns.", "3600", "MX", "10 something.ddns.")
    up.add("rrtest2.ddns.", "3600", "CNAME", "ignore.me.ddns.")
    up.send("NOERROR")
    resp = master.dig("rrtest2.ddns.", "ANY")
    resp.check(rcode="NOERROR")
    resp.check_record(rtype="MX", rdata="10 something.ddns.")
    resp = master.dig("rrtest2.ddns.", "CNAME")
    compare(resp.count(section="answer"), 0, "Added CNAME when it shouldn't")
    verify(master, zone, dnssec)

    # add A to CNAME node, should be ignored
    check_log("Add A to CNAME node")
    up = master.update(zone)
    up.add("cname.ddns.", "3600", "A", "1.2.3.4")
    up.send("NOERROR")
    resp = master.dig("cname.ddns.", "ANY")
    resp.check(rcode="NOERROR")
    resp.check_record(rtype="A", nordata="1.2.3.4")
    resp.check_record(rtype="CNAME", rdata="mail.ddns.")
    verify(master, zone, dnssec)

    # add new node with CNAME + add A to the same node, A should be ignored
    check_log("Add new CNAME node + add A to it")
    up = master.update(zone)
    up.add("rrtest3.ddns.", "3600", "CNAME", "dont.ignore.me.ddns.")
    up.add("rrtest3.ddns.", "3600", "TXT", "ignore")
    up.send("NOERROR")
    resp = master.dig("rrtest3.ddns.", "ANY")
    resp.check(rcode="NOERROR")
    resp.check_record(rtype="TXT", nordata="ignore")
    resp.check_record(rtype="CNAME", rdata="dont.ignore.me.ddns.")
    verify(master, zone, dnssec)

    # add CNAME to CNAME node, should be replaced
    check_log("CNAME to CNAME addition")
    up = master.update(zone)
    up.add("cname.ddns.", 3600, "CNAME", "new-cname.ddns.")
    up.send("NOERROR")
    resp = master.dig("cname.ddns.", "CNAME")
    resp.check(rcode="NOERROR", rdata="new-cname.ddns.")
    resp.check(rcode="NOERROR", nordata="mail.ddns.")
    verify(master, zone, dnssec)

    # add new CNAME node + another CNAME to it; last CNAME should stay in zone
    check_log("Add two CNAMEs to a new node")
    up = master.update(zone)
    up.add("rrtest4.ddns.", "3600", "CNAME", "ignore.me.ddns.")
    up.add("rrtest4.ddns.", "3600", "CNAME", "dont.ignore.me.ddns.")
    up.send("NOERROR")
    resp = master.dig("rrtest3.ddns.", "ANY")
    resp.check(rcode="NOERROR") 
    resp.check_record(rtype="CNAME", rdata="dont.ignore.me.ddns.")
    resp.check_record(rtype="CNAME", nordata="ignore.me.ddns")
    verify(master, zone, dnssec)

    # add SOA with higher than current serial, serial starting from 2010111213
    check_log("Newer SOA addition")
    up = master.update(zone)
    up.add("ddns.", 3600, "SOA",
           "dns1.ddns. hostmaster.ddns. 2011111213 10800 3600 1209600 7200")
    up.send("NOERROR")
    resp = master.dig("ddns.", "SOA")
    resp.check(rcode="NOERROR",
               rdata="dns1.ddns. hostmaster.ddns. 2011111213 10800 3600 1209600 7200")
    verify(master, zone, dnssec)

    # add SOA with higher serial + remove it in the same UPDATE
    # should result in replacing the SOA (i.e. the remove should be ignored)
    check_log("Newer SOA addition + removal")
    up = master.update(zone)
    up.add("ddns.", 3600, "SOA",
           "dns1.ddns. hostmaster.ddns. 2012111213 10800 3600 1209600 7200")
    up.delete("ddns.", "SOA",
           "dns1.ddns. hostmaster.ddns. 2012111213 10800 3600 1209600 7200")
    up.send("NOERROR")
    resp = master.dig("ddns.", "SOA")
    resp.check(rcode="NOERROR",
               rdata="dns1.ddns. hostmaster.ddns. 2012111213 10800 3600 1209600 7200")
    verify(master, zone, dnssec)

    # add SOA with higher serial + remove all SOA in the same UPDATE
    # the removal should be ignored, only replacing the SOA
    check_log("Newer SOA addition + removal of all SOA")
    up = master.update(zone)
    up.add("ddns.", 3600, "SOA",
           "dns1.ddns. hostmaster.ddns. 2013111213 10800 3600 1209600 7200")
    up.delete("ddns.", "SOA")
    up.send("NOERROR")
    resp = master.dig("ddns.", "SOA")
    resp.check(rcode="NOERROR")
    resp.check_record(rtype="SOA", rdata="dns1.ddns. hostmaster.ddns. 2013111213 10800 3600 1209600 7200")
    verify(master, zone, dnssec)

    # add SOA with lower serial, should be ignored
    check_log("Older SOA addition")
    up = master.update(zone)
    up.add("ddns.", 3600, "SOA",
           "dns1.ddns. hostmaster.ddns. 2010111213 10800 3600 1209600 7200")
    up.send("NOERROR")
    resp = master.dig("ddns.", "SOA")
    resp.check(rcode="NOERROR",
               rdata="dns1.ddns. hostmaster.ddns. 2013111213 10800 3600 1209600 7200")
    verify(master, zone, dnssec)

    # add and remove the same record
    check_log("Add and remove same record")
    up = master.update(zone)
    up.add("testaddrem.ddns.", 3600, "TXT", "record")
    up.delete("testaddrem.ddns.", "TXT", "record")
    up.send("NOERROR")
    resp = master.dig("testaddrem.ddns.", "TXT")
    resp.check(rcode="NXDOMAIN")
    verify(master, zone, dnssec)

    # add and remove the same record, delete whole RRSet
    check_log("Add and remove same record, delete whole")
    up = master.update(zone)
    up.add("testaddrem.ddns.", 3600, "TXT", "record")
    up.delete("testaddrem.ddns.", "TXT")
    up.send("NOERROR")
    resp = master.dig("testaddrem.ddns.", "TXT")
    resp.check(rcode="NXDOMAIN")
    verify(master, zone, dnssec)

    # remove non-existent record
    check_log("Remove non-existent record")
    up = master.update(zone)
    up.delete("testaddrem.ddns.", "TXT", "record")
    up.send("NOERROR")
    verify(master, zone, dnssec)

    # remove NS from APEX (NS should stay)
    check_log("Remove NS")
    up = master.update(zone)
    up.delete("ddns.", "NS")
    up.send("NOERROR")
    resp = master.dig("ddns.", "NS")
    resp.check(rcode="NOERROR")
    resp.check_record(rtype="NS", rdata="dns1.ddns.")
    resp.check_record(rtype="NS", rdata="dns2.ddns.")
    verify(master, zone, dnssec)

    # remove all from APEX (NS should stay)
    check_log("Remove all NS")
    up = master.update(zone)
    up.delete("ddns.", "ANY")
    up.send("NOERROR")
    resp = master.dig("ddns.", "NS")
    resp.check(rcode="NOERROR")
    resp.check_record(rtype="NS", rdata="dns1.ddns.")
    resp.check_record(rtype="NS", rdata="dns2.ddns.")
    resp = master.dig("ddns.", "MX")
    resp.check(rcode="NOERROR")
    compare(resp.count(section="answer"), 0, "MX rrset removal")
    verify(master, zone, dnssec)

    # remove all NS + add 1 new; result: 3 RRs
    check_log("Remove all NS + add 1 new")
    up = master.update(zone)
    up.delete("ddns.", "NS")
    up.add("ddns.", 3600, "NS", "dns3.ddns.")
    up.send("NOERROR")
    resp = master.dig("ddns.", "NS")
    resp.check(rcode="NOERROR")
    resp.check_record(rtype="NS", rdata="dns1.ddns.")
    resp.check_record(rtype="NS", rdata="dns2.ddns.")
    resp.check_record(rtype="NS", rdata="dns3.ddns.")
    verify(master, zone, dnssec)

    # remove NSs one at a time + add one new
    # the last one + the new one should remain in the zone
    check_log("Remove NSs one at a time + add 1 new")
    up = master.update(zone)
    up.delete("ddns.", "NS", "dns1.ddns.")
    up.delete("ddns.", "NS", "dns2.ddns.")
    up.delete("ddns.", "NS", "dns3.ddns.")
    up.add("ddns.", 3600, "NS", "dns4.ddns.")
    up.send("NOERROR")
    resp = master.dig("ddns.", "NS")
    resp.check(rcode="NOERROR", nordata="dns1.ddns.")
    resp.check(nordata="dns2.ddns.")
    resp.check_record(rtype="NS", rdata="dns3.ddns.")
    resp.check_record(rtype="NS", rdata="dns4.ddns.")
    verify(master, zone, dnssec)

    # add new NS + remove all one at a time
    # only the new NS should remain in the zone
    check_log("Add 1 NS + remove all NSs one at a time")
    up = master.update(zone)
    up.add("ddns.", 3600, "NS", "dns5.ddns.")
    up.delete("ddns.", "NS", "dns3.ddns.")
    up.delete("ddns.", "NS", "dns4.ddns.")
    up.send("NOERROR")
    resp = master.dig("ddns.", "NS")
    resp.check(rcode="NOERROR", nordata="dns3.ddns.")
    resp.check(nordata="dns4.ddns.")
    resp.check_record(rtype="NS", rdata="dns5.ddns.")
    verify(master, zone, dnssec)

    # add new NS + remove the old one; only the new one should remain
    check_log("Add 1 NS + remove old NS")
    up = master.update(zone)
    up.add("ddns.", 3600, "NS", "dns1.ddns.")
    up.delete("ddns.", "NS", "dns5.ddns.")
    up.send("NOERROR")
    resp = master.dig("ddns.", "NS")
    resp.check(rcode="NOERROR", nordata="dns5.ddns.")
    resp.check_record(rtype="NS", rdata="dns1.ddns.")
    verify(master, zone, dnssec)

    # remove old NS + add new NS; both should remain in the zone
    check_log("Remove old NS + add 1 NS")
    up = master.update(zone)
    up.delete("ddns.", "NS", "dns1.ddns.")
    up.add("ddns.", 3600, "NS", "dns2.ddns.")
    up.send("NOERROR") 
    resp = master.dig("ddns.", "NS")
    resp.check(rcode="NOERROR")
    resp.check_record(rtype="NS", rdata="dns1.ddns.")
    resp.check_record(rtype="NS", rdata="dns2.ddns.")
    verify(master, zone, dnssec)

    # remove NSs one at a time; the last one should remain in the zone
    check_log("Remove NSs one at a time")
    up = master.update(zone)
    up.delete("ddns.", "NS", "dns1.ddns.")
    up.delete("ddns.", "NS", "dns2.ddns.")
    up.send("NOERROR")
    resp = master.dig("ddns.", "NS")
    resp.check(rcode="NOERROR", nordata="dns1.ddns.")
    resp.check_record(rtype="NS", rdata="dns2.ddns.")
    verify(master, zone, dnssec)

    # add new NS + remove ALL NS; should ignore the remove and add the NS
    check_log("Add new NS + remove ALL NSs at once")
    up = master.update(zone)
    up.add("ddns.", 3600, "NS", "dns1.ddns.")
    up.delete("ddns.", "NS")
    up.send("NOERROR")
    resp = master.dig("ddns.", "NS")
    resp.check_record(rtype="NS", rdata="dns1.ddns.")
    resp.check_record(rtype="NS", rdata="dns2.ddns.")
    verify(master, zone, dnssec)

    # add empty generic record
    check_log("Add empty generic record")
    up = master.update(zone)
    up.add("empty.ddns.", 300, "TYPE999", "\# 0")
    up.send("NOERROR")
    resp = master.dig("empty.ddns.", "TYPE999")
    resp.check_record(rtype="TYPE999", rdata="\# 0")
    verify(master, zone, dnssec)

    # add NAPTR record (NAPTR has special processing)
    check_log("Add NAPTR record")
    up = master.update(zone)
    up.add("3.1.1.1.1.1.1.1.1.2.7.9.9.ddns.", 172800, "NAPTR", "1 1 \"u\" \"E2U+sip\" \"!^.*$!sip:123@freeswitch.org!\" .")
    up.send("NOERROR")
    resp = master.dig("3.1.1.1.1.1.1.1.1.2.7.9.9.ddns.", "NAPTR")
    resp.check_record(rtype="NAPTR", rdata="1 1 \"u\" \"E2U+sip\" \"!^.*$!sip:123@freeswitch.org!\" .")
    verify(master, zone, dnssec)

    # modify zone apex
    check_log("Add TXT into apex")
    up = master.update(zone)
    up.add("ddns.", 300, "TXT", "This is apeeex!")
    up.send("NOERROR")
    resp = master.dig("ddns.", "TXT")
    resp.check_record(rtype="TXT", rdata="This is apeeex!")
    verify(master, zone, dnssec)

    if dnssec:
        # add DS for existing delegation
        check_log("DS addition")
        up = master.update(zone)
        up.add("deleg.ddns.", 3600, "DS",
               "54576 10 2 397E50C85EDE9CDE33F363A9E66FD1B216D788F8DD438A57A423A386869C8F06")
        up.send("NOERROR")
        resp = master.dig("deleg.ddns.", "NS", dnssec=True)
        resp.check(rcode="NOERROR")
        resp.check_record(section="authority", rtype="DS",
                          rdata="54576 10 2 397E50C85EDE9CDE33F363A9E66FD1B216D788F8DD438A57A423A386869C8F06")
        resp.check_record(section="authority", rtype="NS", rdata="a.deleg.ddns.")
        resp.check_record(section="authority", rtype="RRSIG")
        verify(master, zone, dnssec)

def do_refusal_tests(master, zone, dnssec=False):

    forbidden = [{'type':"RRSIG", 'data':"A 5 2 1800 20140331062706 20140317095503 132 nic.cz. rc7TwX4GnExDQBNDCdbgf0PS7zabtymSKQ0VhmbFJAcYZxN+yFF9PXAo SpsDVR5H0PIuUM4oqoe7gsKfqqpTdOuB9M6cN/Mni99u7XfKHkopDjYc qTJXKn3x2TER4WkGtG5uthuSEc9lseCr6XqAqkDnJlUa6pB2a3mEHwu/ Elk="},
                 {'type':"NSEC",  'data':"0-0.se. NS SOA TXT RRSIG NSEC DNSKEY"},
                 {'type':"NSEC3", 'data':"1 0 10 B8399FF56C1C0C7E D0RS5MTK2AT5SVG2S9LRMM4L2J63V6GL NS"}]

    # Store initial SOA
    soa_resp = master.dig("ddns.", "SOA")
    prev_soa = soa_resp.resp.answer

    # Add DDNS forbidden records
    check_log("Adding forbidden records")
    for f in forbidden:
        up = master.update(zone)
        up.add("forbidden.ddns.", 3600, f['type'], f['data'])
        up.send("REFUSED")
        resp = master.dig("forbidden.ddns", "ANY")
        resp.check(rcode="NXDOMAIN")
        check_soa(master, prev_soa)

    # Remove DDNS forbidden records
    check_log("Removing forbidden records")
    for f in forbidden:
        up = master.update(zone)
        up.delete("forbidden.ddns.", f['type'])
        up.send("REFUSED")
        check_soa(master, prev_soa)

    # Add normal records and then forbidden one
    check_log("Refusal rollback")
    up = master.update(zone)
    up.add("rollback.ddns.", 3600, "TXT", "do not add me")
    up.add("forbidden.ddns.", 3600, forbidden[0]['type'], forbidden[0]['data'])
    up.send("REFUSED")
    resp = master.dig("rollback.ddns", "ANY")
    resp.check(rcode="NXDOMAIN")
    resp = master.dig("forbidden.ddns", "ANY")
    resp.check(rcode="NXDOMAIN")
    check_soa(master, prev_soa)

    # Add DNAME children
    check_log("Add DNAME children rollback")
    up = master.update(zone)
    up.add("rollback.ddns.", 3600, "TXT", "do not add me")
    up.add("under.dname.ddns.", 3600, "DNAME", "ddns.")
    up.send("REFUSED")
    resp = master.dig("rollback.ddns", "ANY")
    resp.check(rcode="NXDOMAIN")
    check_soa(master, prev_soa)

    # Out-of-zone data
    check_log("Out-of-zone data")
    up = master.update(zone)
    up.add("what.the.hell.am.i.doing.here.", "3600", "TXT", "I don't belong here")
    up.send("NOTZONE")
    check_soa(master, prev_soa)

    # Remove 'all' SOA, ignore
    check_log("Remove all SOA")
    up = master.update(zone)
    up.delete("ddns.", "SOA")
    up.send("NOERROR")
    check_soa(master, prev_soa)

    # Remove specific SOA, ignore
    check_log("Remove specific SOA")
    up = master.update(zone)
    up.delete("ddns.", "SOA", "dns1.ddns. hostmaster.ddns. 2011111213 10800 3600 1209600 7200")
    up.send("NOERROR")
    check_soa(master, prev_soa)

    if dnssec:
        # Add DNSKEY
        check_log("DNSKEY addition")
        up = master.update(zone)
        up.add("ddns.", "3600", "DNSKEY",
               "256 3 5 AwEAAbs0AlA6xWQn/lECfGt3S6TaeEmgJfEVVEMh06iNMNWMRHOfbqLF h3N52Ob7trmzlrzGlGLPnAZJvMB8lsFGC5CtaLUBD+4xCh5tl5QifZ+y o+MJvPGlVQI2cs7aMWV9CyFrRmuRcJaSZU2uBz9KFJ955UCq/WIy5KqS 7qaKLzzN")
        up.send("REFUSED")
        resp = master.dig("ddns.", "DNSKEY")
        resp.check(rcode="NOERROR",
                   nordata="256 3 5 AwEAAbs0AlA6xWQn/lECfGt3S6TaeEmgJfEVVEMh06iNMNWMRHOfbqLF h3N52Ob7trmzlrzGlGLPnAZJvMB8lsFGC5CtaLUBD+4xCh5tl5QifZ+y o+MJvPGlVQI2cs7aMWV9CyFrRmuRcJaSZU2uBz9KFJ955UCq/WIy5KqS 7qaKLzzN")

        # Add NSEC3PARAM
        check_log("NSEC3PARAM addition")
        up = master.update(zone)
        up.add("ddns.", "0", "NSEC3PARAM", "1 0 10 B8399FF56C1C0C7E")
        up.send("REFUSED")
        resp = master.dig("ddns.", "NSEC3PARAM")
        resp.check(rcode="NOERROR", nordata="1 0 10 B8399FF56C1C0C7E")

        check_soa(master, prev_soa)

        # Add DNSKEY
        check_log("non-apex DNSKEY addition")
        up = master.update(zone)
        up.add("nonapex.ddns.", "3600", "DNSKEY",
               "256 3 5 AwEAAbs0AlA6xWQn/lECfGt3S6TaeEmgJfEVVEMh06iNMNWMRHOfbqLF h3N52Ob7trmzlrzGlGLPnAZJvMB8lsFGC5CtaLUBD+4xCh5tl5QifZ+y o+MJvPGlVQI2cs7aMWV9CyFrRmuRcJaSZU2uBz9KFJ955UCq/WIy5KqS 7qaKLzzN")
        up.send("NOERROR")
        resp = master.dig("nonapex.ddns.", "DNSKEY")
        resp.check(rcode="NOERROR",
                   rdata="256 3 5 AwEAAbs0AlA6xWQn/lECfGt3S6TaeEmgJfEVVEMh06iNMNWMRHOfbqLF h3N52Ob7trmzlrzGlGLPnAZJvMB8lsFGC5CtaLUBD+4xCh5tl5QifZ+y o+MJvPGlVQI2cs7aMWV9CyFrRmuRcJaSZU2uBz9KFJ955UCq/WIy5KqS 7qaKLzzN")

zone = t.zone("ddns.", storage=".")

master_plain = t.server("knot")
t.link(zone, master_plain, ddns=True)

master_nsec = t.server("knot")
t.link(zone, master_nsec, ddns=True)
master_nsec.dnssec(zone).enable = True

master_nsec3 = t.server("knot")
t.link(zone, master_nsec3, ddns=True)
master_nsec3.dnssec(zone).enable = True
master_nsec3.dnssec(zone).nsec3 = True

t.start()

# DNSSEC-less test
check_log("============ Plain test ===========")
do_normal_tests(master_plain, zone)
do_refusal_tests(master_plain, zone)

# DNSSEC with NSEC test
check_log("============ NSEC test ============")
do_normal_tests(master_nsec, zone, dnssec=True)
do_refusal_tests(master_nsec, zone, dnssec=True)

# DNSSEC with NSEC3 test
check_log("============ NSEC3 test ===========")
do_normal_tests(master_nsec3, zone, dnssec=True)
do_refusal_tests(master_nsec3, zone, dnssec=True)

t.end()
