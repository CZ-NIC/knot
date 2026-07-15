#!/usr/bin/env python3

'''Test of DDNS forwarding over QUIC.'''

import random
import subprocess
from dnstest.test import Test
from dnstest.keys import Tsig
from dnstest.utils import *

t = Test(quic=True, tsig=False)

master = t.server("knot", xdp_enable=False)
slave = t.server("knot", xdp_enable=False)
zones = t.zone_rnd(2)

t.link(zones, master, slave, ddns=True)

t.start()

tcpdump_pcap = t.out_dir + "/traffic.pcap"
tcpdump_fout = t.out_dir + "/tcpdump.out"
tcpdump_ferr = t.out_dir + "/tcpdump.err"

tcpdump_proc = subprocess.Popen(["tcpdump", "-i", "lo", "-w", tcpdump_pcap,
                                 "port", str(master.quic_port), "or", "port", str(slave.quic_port)],
                                stdout=open(tcpdump_fout, mode="a"), stderr=open(tcpdump_ferr, mode="a"))

try:
    serials = slave.zones_wait(zones)

    for tries in [1, 2]:
        for z in zones:
            up = slave.update(z)
            up.add("jfdowijfiowjdw%d" % tries, 3600, "TXT", "djpeidjwe")
            up.send()
        serials = slave.zones_wait(zones, serials)

    t.xfr_diff(master, slave, zones)
finally:
    tcpdump_proc.terminate()

if slave.log_search("QUIC/0-RTT, successfully forwarded"):
    set_err("0-RTT used for DDNS")

t.end()
