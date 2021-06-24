#!/usr/bin/env python3

"""
Test of RFC 5011 revoked key feature.
"""

from dnstest.utils import *
from dnstest.keys import Keymgr
from dnstest.test import Test

ZONE = "example.com."

def wait_for_rrsig_count(t, server, rrtype, rrsig_count, timeout):
    rtime = 0.0
    while True:
        qdnskeyrrsig = server.dig(ZONE, rrtype, dnssec=True, bufsize=4096)
        found_rrsigs = qdnskeyrrsig.count("RRSIG")
        if found_rrsigs == rrsig_count:
            break
        rtime = rtime + 0.1
        t.sleep(0.1)
        if rtime > timeout:
            break

def check_revoked_key(server):
    resp = server.dig(ZONE, "DNSKEY", dnssec=True)
    cnt = resp.count("DNSKEY")
    if cnt < 1:
        set_err("No DNSKEYS")
    found = False
    for rr in resp.resp.answer[0].to_rdataset():
        if rr.to_text().split()[0] == "385":
            found = True
    if not found:
        set_err("No revoked key")
        detail_log("No revoked key")
        for rr in resp.resp.answer[0].to_rdataset():
            detail_log(rr.to_text())

t = Test()

knot = t.server("knot")
zone = t.zone(ZONE)
t.link(zone, knot)
knot.dnssec(zone).enable = True
knot.dnssec(zone).manual = True

# needed for keymgr
knot.gen_confile()

# scenario 1: plan revoked timestamp in the future
knot.key_gen(ZONE, ksk="true", created="+0", publish="+0", ready="+0", active="+0", retire="+12s", revoke="+15s", remove="+18s")
knot.key_gen(ZONE, ksk="false", created="+0", publish="+0", ready="0", active="+0", retire="+1d", remove="+1d")
KSK = knot.key_gen(ZONE, ksk="true", created="+0", publish="+0", ready="+10s", active="+10s")

t.start()
knot.zone_wait(zone)

wait_for_rrsig_count(t, knot, "DNSKEY", 2, 2)
wait_for_rrsig_count(t, knot, "DNSKEY", 1, 10)
wait_for_rrsig_count(t, knot, "DNSKEY", 2, 3)
check_revoked_key(knot)

# scenario 2: plan revoked timestamp in the past
wait_for_rrsig_count(t, knot, "DNSKEY", 1, 3)

knot.key_gen(ZONE, ksk="true", created="+0", publish="+0", ready="+0", active="+0")
knot.key_set(ZONE, KSK, retire="+0", revoke="+0", remove="+8s")

t.sleep(2)
knot.ctl("zone-keys-load")
t.sleep(2)
check_revoked_key(knot)

# scenario 3: import revoked key from Bind
wait_for_rrsig_count(t, knot, "DNSKEY", 1, 6)

Keymgr.run_check(knot.confile, ZONE, "import-bind", knot.data_dir + "/Kexample.com.+013+65449.key")

knot.ctl("zone-keys-load")
t.sleep(2)
check_revoked_key(knot)

t.end()
