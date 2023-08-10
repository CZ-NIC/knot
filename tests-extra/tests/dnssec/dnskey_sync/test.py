#!/usr/bin/env python3

"""
Check of multi-signer DNSKEY synchronization.
"""

import random
import datetime
from dnstest.utils import *
from dnstest.keys import Keymgr
from dnstest.test import Test

SCENARIO = random.choice(range(36))
CDS = bool(SCENARIO % 2)
DNSKEY_MASTER = 0 # ((SCENARIO // 2) % 3) # scenario with on-master-DNSKEYs is not supported since we would need benevolent-IXFR on signers
SIGNERS3 = bool((SCENARIO // 2) % 2)
SIGNER1ROLL = (SCENARIO // 4) % 3
SIGNER2ROLL = (SCENARIO // 4) // 3
ROLL_LOG = [ "ZSK", "KSK", "CSK" ]
check_log("SCENARIO %d, SIGNERS3 enabled %s, SIGNER1ROLL %s, SIGNER2ROLL %s, CDS enabled %s, DNSKEY master %d" % \
          (SCENARIO, SIGNERS3, ROLL_LOG[SIGNER1ROLL], ROLL_LOG[SIGNER2ROLL], str(CDS), DNSKEY_MASTER))

def now_hms(shift):
    t = datetime.datetime.now()
    t = t + datetime.timedelta(seconds=shift)
    return t.strftime("%H:%M:%S")

def detect_ddns_deadlock(server):
    lastline=""
    with open(server.fout, "r") as fl:
        for line in fl:
            lastline = line

    #detect recent (any) activity in the logfile so that servers settle down before equivalence test
    if now_hms(0) in lastline:
        return True
    if now_hms(-1) in lastline:
        return True
    if now_hms(-2) in lastline:
        return True
    return False

def check_same_dnskey(server1, server2, server3, tst):
    while detect_ddns_deadlock(server1) or detect_ddns_deadlock(server2) or \
          (SIGNERS3 and detect_ddns_deadlock(server3)):
        tst.sleep(6)

    dnskey1 = server1.dig(zone[0].name, "DNSKEY", udp=False)
    dnskey2 = server2.dig(zone[0].name, "DNSKEY", udp=False)
    dnskey1.diff(dnskey2)
    if SIGNERS3:
        dnskey3 = server3.dig(zone[0].name, "DNSKEY", udp=False)
        dnskey2.diff(dnskey3)

    server1.flush(zone[0], wait=True)
    server1.zone_verify(zone)
    server2.flush(zone[0], wait=True)
    server2.zone_verify(zone)
    if SIGNERS3:
        server3.flush(zone[0], wait=True)
        server3.zone_verify(zone)

def configure_dnssec(server1, master, server2, server3, roll):
    t.link(zone, master, server1, ddns=True)
    server1.tcp_remote_io_timeout = 1500
    if DNSKEY_MASTER < 2:
        server1.ddns_master = ""

    server1.dnssec(zone).enable = True
    server1.dnssec(zone).single_type_signing = (roll == 2)
    server1.dnssec(zone).propagation_delay = 4
    server1.dnssec(zone).ksk_sbm_timeout = 4
    server1.dnssec(zone).dnskey_mgmt = "incremental"
    server1.dnssec(zone).delete_delay = 4
    server1.dnssec(zone).cds_publish = ("always" if CDS else "none")
    if DNSKEY_MASTER == 1:
        server1.dnssec(zone).dnskey_sync = [ master ]
    else:
        server1.dnssec(zone).dnskey_sync = [ server2, server3 ] if SIGNERS3 else [ server2 ]

t = Test()

master = t.server("knot")
signer1 = t.server("knot")
signer2 = t.server("knot")
signer3 = t.server("knot")
zone = t.zone("catalog.") # has zero TTL => faster key rollovers

configure_dnssec(signer1, master, signer2, signer3, SIGNER1ROLL)
configure_dnssec(signer2, master, signer3 if SIGNERS3 else signer1, signer1, SIGNER2ROLL)
if SIGNERS3:
    configure_dnssec(signer3, master, signer1, signer2, SIGNER2ROLL)

t.start()
signer1.zone_wait(zone)
signer2.zone_wait(zone)
if SIGNERS3:
    signer3.zone_wait(zone)

t.sleep(4)
check_same_dnskey(signer1, signer2, signer3, t)

signer1.ctl("zone-key-rollover %s %s" % (zone[0].name, "zsk" if SIGNER1ROLL == 0 else "ksk"))
t.sleep(0.5)
signer2.ctl("zone-key-rollover %s %s" % (zone[0].name, "zsk" if SIGNER2ROLL == 0 else "ksk"))
if SIGNERS3:
    t.sleep(0.5)
    signer3.ctl("zone-key-rollover %s %s" % (zone[0].name, "zsk" if SIGNER2ROLL == 0 else "ksk"))

t.sleep(6)
check_same_dnskey(signer1, signer2, signer3, t)

t.sleep(6)
check_same_dnskey(signer1, signer2, signer3, t)

t.end()
