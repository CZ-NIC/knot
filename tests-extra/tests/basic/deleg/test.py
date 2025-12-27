#!/usr/bin/env python3

'''Various tests of DELEG-aware and unaware auth server answering.'''

from dnstest.test import Test
from dnstest.utils import *
import shutil

DELEGATIONS = [ "ns.d.xdp.cz.", "ns-ds.d.xdp.cz.", "deleg.d.xdp.cz.", "deleg-ds.d.xdp.cz.", "deleg-ns.d.xdp.cz.", "deleg-ns-ds.d.xdp.cz." ]

def check_normal(resp, presence, rrtype): # check positive answer or NODATA
    resp.check(rcode="NOERROR")
    resp.check_count(0, "NS", section="authority")
    resp.check_count(0, "TYPE61440", section="authority")
    if presence:
        resp.check_count(1, rrtype, section="answer")
    else:
        resp.check_count(1, "SOA", section="authority")
        resp.check_count(1, "NSEC", section="authority")

def check_delegation(resp, D, debit):
    resp.check(rcode="NOERROR")
    resp.check_count(0, "A", section="answer")
    resp.check_count(0, "TYPE61440", section="answer")
    if debit and ("deleg" in D):
        resp.check_count(1, "TYPE61440", section="authority")
    else:
        resp.check_count(1, "NS", section="authority")
    if "ds" in D:
        resp.check_count(1, "DS", section="authority")
    else:
        resp.check_count(1, "NSEC", section="authority")
    if (resp.resp.ednsflags & (1<<13)) != ((1<<13) if debit else 0): # resp.check(noeflags=...) requires DEflag support in dnspython
        set_err("%sDE flag in response" % ("no " if debit else ""))

def check_nxdomain(resp, nsec_count):
    resp.check(rcode="NXDOMAIN")
    resp.check_count(0, "A", section="answer")
    resp.check_count(0, "TYPE61440", section="answer")
    resp.check_count(0, "TYPE61440", section="authority")
    resp.check_count(1, "SOA", section="authority")
    resp.check_count(nsec_count, "NSEC", section="authority")
    resp.check_count(0, "NS", section="authority")

t = Test()

knot = t.server("knot")
parent = t.zone("d.xdp.cz.", storage=".")
childs = []
shutil.copy(os.path.join(t.data_dir, "child-generic.zone"), os.path.join(knot.dir, "child-generic.zone"))
for childz in DELEGATIONS:
    zf = os.path.join(knot.dir, "%szone" % childz)
    shutil.copy(os.path.join(t.data_dir, "child-generic.zone"), zf)
    childs += t.zone(childz, file_name=zf)

t.link(parent, knot)
knot.dnssec(parent).enable = True
t.start()
knot.zone_wait(parent)

for childs_running in [ False, True ]:

    if childs_running and DELEGATIONS[0] not in knot.zones:
        t.link(childs, knot)
        knot.dnssec(childs).enable = True
        knot.gen_confile()
        knot.reload()
        serials = knot.zones_wait(childs)

    for debit in [ False, True ]:
        for D in DELEGATIONS:
            understood = (debit or ("ns" in D)) # the client understands that there IS a delegation

            resp = knot.dig("dns1." + D, "A", dnssec=True, de=debit)
            if childs_running: # direct answer from child zone
                check_normal(resp, True, "A")
            elif understood:
                check_delegation(resp, D, debit)
            else:
                check_nxdomain(resp, 1)

            resp = knot.dig("dns2." + D, "A", dnssec=True, de=debit)
            if childs_running:
                check_nxdomain(resp, 2)
            elif understood:
                check_delegation(resp, D, debit)
            else:
                check_nxdomain(resp, 1)

            resp = knot.dig(D, "DS", dnssec=True, de=debit)
            check_normal(resp, "ds" in D, "DS")

            resp = knot.dig(D, "TYPE61440", dnssec=True, de=debit)
            if debit:
                check_normal(resp, "deleg" in D, "TYPE61440")
            elif childs_running:
                check_normal(resp, False, "TYPE61440")
            elif "ns" in D: # understood
                check_delegation(resp, D, debit)
            else:
                check_normal(resp, True, "TYPE61440")

            resp = knot.dig(D, "NS", dnssec=True, de=debit)
            if childs_running:
                check_normal(resp, True, "NS")
            elif understood:
                check_delegation(resp, D, debit)
            else:
                check_normal(resp, False, "NS")

            resp = knot.dig(D, "A", dnssec=True, de=debit)
            if childs_running:
                check_normal(resp, False, "A")
            elif understood:
                check_delegation(resp, D, debit)
            else:
                check_normal(resp, False, "A")

resp = knot.dig(parent[0].name, "DNSKEY")
if resp.resp.answer[0].to_rdataset()[0].flags & 2 != 2:
    set_err("No ADT flag")
resp = knot.dig(childs[0].name, "DNSKEY")
if resp.resp.answer[0].to_rdataset()[0].flags & 2 != 0:
    set_err("Extra ADT flag")

# incremental addition of DELEG -- temporary ADT DNSKEY
Z = "ns-ds.d.xdp.cz."
up = knot.update(knot.zones[Z])
up.add("deleg", 30, "TYPE61440", "\\# 8 0001000401020304")
up.send("NOERROR")
knot.zone_wait(knot.zones[Z], serials[Z])
resp = knot.dig(Z, "DNSKEY")
adt_found = False
for dnskey_rr in resp.resp.answer[0].to_rdataset():
    adt_found = adt_found or (dnskey_rr.flags & 2 != 0)
if not adt_found:
    set_err("No ADT temporary DNSKEY")

knot.ctl("zone-flush", wait=True)

t.end()
