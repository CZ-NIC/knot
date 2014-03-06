#!/usr/bin/env python3

'''Manual DDNS testing'''

from dnstest.utils import *
from dnstest.test import Test

def verify(master, zone, dnssec):
  if not dnssec:
    return
  master.flush()
  t.sleep(1)
  master.zone_verify(zone)

def do_test(master, zone, dnssec=False):
  # add record
  check_log("Record addition")
  up = master.update(zone)
  up.add("rrtest.ddns.", 3600, "A", "1.2.3.4")
  up.send("NOERROR")
  resp = master.dig("rrtest.ddns.", "A")
  resp.check(rcode="NOERROR", rdata="1.2.3.4")
  verify(master, zone, dnssec)
  detail_log(SEP)

  # add record to existing node
  check_log("Node update")
  up = master.update(zone)
  up.add("rrtest.ddns.", 3600, "TXT", "abcedf")
  up.send("NOERROR")
  resp = master.dig("rrtest.ddns.", "TXT")
  resp.check(rcode="NOERROR", rdata="abcedf")
  verify(master, zone, dnssec)
  detail_log(SEP)

  # remove record
  check_log("Record removal")
  up = master.update(zone)
  up.delete("rrtest.ddns.", "A", "1.2.3.4")
  up.send("NOERROR")
  resp = master.dig("rrtest.ddns.", "A")
  resp.check(rcode="NOERROR")
  if (resp.count(section="answer") > 0):
    check_log("Did not delete A record")
    set_err("Did not delete A record")
  verify(master, zone, dnssec)
  detail_log(SEP)

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
  detail_log(SEP)

  # add DS for existing delegation
  if dnssec:
    check_log("DS addition")
    up = master.update(zone)
    up.add("deleg.ddns.", 3600, "DS", "54576 10 2 397E50C85EDE9CDE33F363A9E66FD1B216D788F8DD438A57A423A386869C8F06")
    up.send("NOERROR")
    resp = master.dig("deleg.ddns.", "NS", dnssec=True)
    resp.check(rcode="NOERROR")
    resp.check_record(section="authority", rtype="DS", rdata="54576 10 2 397E50C85EDE9CDE33F363A9E66FD1B216D788F8DD438A57A423A386869C8F06")
    resp.check_record(section="authority", rtype="NS", rdata="a.deleg.ddns.")
    verify(master, zone, dnssec)
    detail_log(SEP)

  # remove all from APEX (NS should stay)
  check_log("Remove all")
  up = master.update(zone)
  up.delete("ddns.", "ANY")
  up.send("NOERROR")
  resp = master.dig("ddns.", "NS")
  resp.check(rcode="NOERROR")
  resp.check_record(rtype="NS", rdata="dns1.ddns.")
  resp.check_record(rtype="NS", rdata="dns2.ddns.")
  resp = master.dig("ddns.", "MX")
  resp.check(rcode="NOERROR")
  if (resp.count(section="answer") > 0):
    set_err("DID NOT DELETE MX")
  verify(master, zone, dnssec)
  detail_log(SEP)

  # add and remove the same record
  check_log("Add and remove same record")
  up = master.update(zone)
  up.add("testaddrem.ddns.", 3600, "TXT", "record")
  up.delete("testaddrem.ddns.", "TXT")
  up.send("NOERROR")
  resp = master.dig("testaddrem.ddns.", "TXT")
  resp.check(rcode="NXDOMAIN")
  verify(master, zone, dnssec)
  detail_log(SEP)

t = Test()

zone = t.zone("ddns.", "ddns.zone", storage=".")
master_plain = t.server("knot")
t.link(zone, master_plain, ddns=True)

master_nsec = t.server("knot")
t.link(zone, master_nsec, ddns=True)
master_nsec.dnssec_enable = True
master_nsec.gen_key(zone, ksk=True, alg="RSASHA256")
master_nsec.gen_key(zone, alg="RSASHA256")
master_nsec.gen_confile()

master_nsec3 = t.server("knot")
t.link(zone, master_nsec3, ddns=True)
master_nsec3.dnssec_enable = True
master_nsec3.gen_key(zone, ksk=True, alg="RSASHA256")
master_nsec3.gen_key(zone, alg="RSASHA256")
master_nsec3.gen_confile()
master_nsec3.enable_nsec3(zone)

t.start()

detail_log(SEP)
detail_log(" ============ Plain test ===========")
detail_log(SEP)

# DNSSEC-less test
do_test(master_plain, zone)

detail_log(SEP)
detail_log(" ============ NSEC test ============")
detail_log(SEP)

# test with NSEC
do_test(master_nsec, zone, dnssec=True)

detail_log(SEP)
detail_log(" ============ NSEC3 test ===========")
detail_log(SEP)

# test with NSEC3
do_test(master_nsec3, zone, dnssec=True)

t.end()
