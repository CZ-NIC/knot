#!/usr/bin/env python3

'''Test of zone transfers over QUIC.'''

from dnstest.test import Test
from dnstest.utils import *
import random
import subprocess

t = Test(quic=True, tsig=True) # TSIG needed to skip weaker ACL rules

master = t.server("knot")
slave = t.server("knot")
rnd_zones = t.zone_rnd(1, records=50) + \
            t.zone_rnd(1, records=500) + \
            t.zone_rnd(1, records=1000)
zones = t.zone(".") + rnd_zones

t.link(zones, master, slave)

for z in zones:
    master.zones[z.name].zfile.update_soa(retry=10) # WARNING this inhibits the effect of some issue that QUIC communication fails sometimes. This SHOULD be removed and the QUIC issue fixed!

for z in rnd_zones:
    master.dnssec(z).enable = True

if master.valgrind:
    slave.quic_idle_close_timeout = 10 # for DoQ xfrs
    slave.tcp_remote_io_timeout = 10000
if slave.valgrind:
    master.quic_idle_close_timeout = 10 # for sending DoQ notify

MSG_DENIED_NOTIFY = "ACL, denied, action notify"
MSG_DENIED_TRANSFER = "ACL, denied, action transfer"
MSG_RMT_NOTAUTH = "server responded with error 'NOTAUTH'"
MSG_RMT_BADCERT = "failed (unknown certificate key/untrusted certificate)"
MSG_TSIG_ERROR = "failed (failed to verify TSIG)"

def check_error(server, msg):
    for i in range(10):
        if server.log_search(msg):
            return
        t.sleep(1)
    detail_log("Failed log expected '%s' server %s" % (msg, server.name))
    set_err("MISSING ERROR LOG")

def upd_check_zones(master, slave, zones, prev_serials):
    for z in rnd_zones:
        master.random_ddns(z, allow_empty=False)
    serials = slave.zones_wait(zones, prev_serials)
    t.xfr_diff(master, slave, zones, prev_serials)
    return serials

master.check_quic()

t.start()

tcpdump_pcap = t.out_dir + "/traffic.pcap"
tcpdump_fout = t.out_dir + "/tcpdump.out"
tcpdump_ferr = t.out_dir + "/tcpdump.err"

tcpdump_proc = subprocess.Popen(["tcpdump", "-i", "lo", "-w", tcpdump_pcap,
                                 "port", str(master.quic_port), "or", "port", str(slave.quic_port)],
                                stdout=open(tcpdump_fout, mode="a"), stderr=open(tcpdump_ferr, mode="a"))

try:
    # Check initial AXFR without cert-key-based authentication
    serials = master.zones_wait(zones)
    slave.zones_wait(zones, serials, equal=True, greater=False)
    if slave.log_search(MSG_TSIG_ERROR):
        set_err("INCOMPLETE TRANSFER")
    t.xfr_diff(master, slave, zones)

    # Check master not authenticated due to bad cert-key
    master.cert_key = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
    slave.gen_confile()
    slave.reload()
    master.ctl("zone-notify")
    check_error(master, MSG_RMT_NOTAUTH)
    check_error(slave, MSG_DENIED_NOTIFY)
    slave.ctl("zone-retransfer")
    check_error(slave, MSG_RMT_BADCERT)

    # Check IXFR with cert-key-based authenticated master
    master.fill_cert_key()
    slave.gen_confile()
    slave.reload()
    serials = upd_check_zones(master, slave, rnd_zones, serials)

    # Check slave not authenticated due to bad cert-key
    slave.cert_key = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
    master.gen_confile()
    master.reload()
    master.ctl("zone-notify")
    check_error(master, MSG_RMT_BADCERT)
    slave.ctl("zone-retransfer")
    check_error(slave, MSG_RMT_NOTAUTH)
    check_error(master, MSG_DENIED_TRANSFER)

    # Check IXFR with cert-key-based authenticated slave
    slave.fill_cert_key()
    master.gen_confile()
    master.reload()
    serials = upd_check_zones(master, slave, rnd_zones, serials)

finally:
    tcpdump_proc.terminate()

if not master.log_search("QUIC/0-RTT") or not slave.log_search("QUIC/0-RTT"):
    set_err("0-RTT NOT WORKING")

t.end()
