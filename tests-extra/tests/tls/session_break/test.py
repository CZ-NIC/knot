#!/usr/bin/env python3

'''Test of session resumtpion to restarted server.'''

from dnstest.test import Test
from dnstest.utils import *
import random
import subprocess

t = Test(tls=True, tsig=True) # TSIG needed to skip weaker ACL rules

master = t.server("knot")
slave = t.server("knot")
zones = t.zone("example.")

t.link(zones, master, slave)
#
# for z in rnd_zones:
#     master.dnssec(z).enable = True
#
# if master.valgrind:
#     slave.quic_idle_close_timeout = 10 # for DoQ xfrs
#     master.tcp_io_timeout = 10000
#     slave.tcp_io_timeout = 10000
#     master.tcp_remote_io_timeout = 10000
#     slave.tcp_remote_io_timeout = 10000
# if slave.valgrind:
#     master.quic_idle_close_timeout = 10 # for sending DoQ notify
#
# MSG_DENIED_NOTIFY = "ACL, denied, action notify"
# MSG_DENIED_TRANSFER = "ACL, denied, action transfer"
# MSG_RMT_NOTAUTH = "server responded with error 'NOTAUTH'"
# MSG_RMT_BADCERT = "failed (invalid certificate)"
# MSG_TSIG_ERROR = "failed (failed to verify TSIG)"
#
# def check_error(server, msg):
#     for i in range(10):
#         if server.log_search(msg):
#             return
#         t.sleep(1)
#     detail_log("Failed log expected '%s' server %s" % (msg, server.name))
#     set_err("MISSING ERROR LOG")
#
# def upd_check_zones(master, slave, zones, prev_serials):
#     for z in rnd_zones:
#         master.random_ddns(z, allow_empty=False)
#     serials = slave.zones_wait(zones, prev_serials)
#     t.xfr_diff(master, slave, zones, prev_serials)
#     return serials
#
# master.check_quic()

t.gen_ca()

t.start()

tcpdump_pcap = t.out_dir + "/traffic.pcap"
tcpdump_fout = t.out_dir + "/tcpdump.out"
tcpdump_ferr = t.out_dir + "/tcpdump.err"

tcpdump_proc = subprocess.Popen(["tcpdump", "-i", "lo", "-w", tcpdump_pcap,
                                 "port", str(master.tls_port), "or", "port", str(slave.tls_port)],
                                stdout=open(tcpdump_fout, mode="a"), stderr=open(tcpdump_ferr, mode="a"))

try:
    serial = master.zone_wait(zones)
    slave.zone_wait(zones, serial, equal=True, greater=False)
    t.xfr_diff(master, slave, zones)

    master.stop()
    master.zones[zones[0].name].zfile.update_soa()
    master.start()

    serial = master.zone_wait(zones, serial)
    slave.zone_wait(zones, serial, equal=True, greater=False)
    t.xfr_diff(master, slave, zones)

    slave.ctl("zone-retransfer")
    t.sleep(2)
    t.xfr_diff(master, slave, zones)

finally:
    tcpdump_proc.terminate()

if not slave.log_search("TLS/0-RTT"):
    set_err("0-RTT NOT WORKING")

t.end()
