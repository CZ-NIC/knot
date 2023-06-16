#!/usr/bin/env python3

"""
Check of multi-signer DNSKEY synchronization.
"""

import random
from dnstest.utils import *
from dnstest.keys import Keymgr
from dnstest.test import Test

SCENARIO = random.choice(range(54))
CDS = bool(SCENARIO % 2)
DNSKEY_MASTER = 0 # ((SCENARIO // 2) % 3) # scenario with on-master-DNSKEYs is not supported since we would need benevolent-IXFR on signers
SIGNER1ROLL = (SCENARIO // 6) % 3
SIGNER2ROLL = (SCENARIO // 6) // 3
ROLL_LOG = [ "ZSK", "KSK", "CSK" ]
check_log("SCENARIO %d, SIGNER1ROLL %s, SIGNER2ROLL %s, CDS enabled %s, DNSKEY master %d" % \
          (SCENARIO, ROLL_LOG[SIGNER1ROLL], ROLL_LOG[SIGNER2ROLL], str(CDS), DNSKEY_MASTER))

def detect_ddns_deadlock(server):
    lastline=""
    with open(server.fout, "r") as fl:
        for line in fl:
            lastline = line
    if "ACL, allowed, action update" in lastline:
        return True
    return False

def check_same_dnskey(server1, server2, tst):
    while detect_ddns_deadlock(server1) or detect_ddns_deadlock(server2):
        tst.sleep(6)

    dnskey1 = server1.dig(zone[0].name, "DNSKEY")
    dnskey2 = server2.dig(zone[0].name, "DNSKEY")
    dnskey1.diff(dnskey2)

    server1.flush(zone[0], wait=True)
    server1.zone_verify(zone)
    server2.flush(zone[0], wait=True)
    server2.zone_verify(zone)

def configure_dnssec(server1, server2, roll):
    server1.dnssec(zone).enable = True
    server1.dnssec(zone).single_type_signing = (roll == 2)
    server1.dnssec(zone).propagation_delay = 4
    server1.dnssec(zone).ksk_sbm_timeout = 4
    server1.dnssec(zone).dnskey_mgmt = "incremental"
    server1.dnssec(zone).delete_delay = 4
    server1.dnssec(zone).cds_publish = ("always" if CDS else "none")
    server1.dnssec(zone).dnskey_sync = [ server2 ]

t = Test()

master = t.server("knot")
signer1 = t.server("knot")
signer2 = t.server("knot")
zone = t.zone("catalog.") # has zero TTL => faster key rollovers
t.link(zone, master, signer1, ddns=True)
t.link(zone, master, signer2, ddns=True)
if DNSKEY_MASTER < 2:
    signer1.ddns_master = ""
    signer2.ddns_master = ""

configure_dnssec(signer1, (master if DNSKEY_MASTER == 1 else signer2), SIGNER1ROLL)
configure_dnssec(signer2, (master if DNSKEY_MASTER == 1 else signer1), SIGNER2ROLL)

t.start()
signer1.zone_wait(zone)
signer2.zone_wait(zone)

t.sleep(4)
check_same_dnskey(signer1, signer2, t)

signer1.ctl("zone-key-rollover %s %s" % (zone[0].name, "zsk" if SIGNER1ROLL == 0 else "ksk"))
signer2.ctl("zone-key-rollover %s %s" % (zone[0].name, "zsk" if SIGNER2ROLL == 0 else "ksk"))

t.sleep(6)
check_same_dnskey(signer1, signer2, t)

t.sleep(6)
check_same_dnskey(signer1, signer2, t)

t.end()
