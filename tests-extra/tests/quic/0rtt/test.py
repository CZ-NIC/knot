#!/usr/bin/env python3

'''Test of 0-RTT over QUIC.'''

from dnstest.test import Test
from dnstest.utils import *
import pathlib
import random
import subprocess

SCRIPT = pathlib.Path(__file__).parent / "data" / "quic_client.py"

def resp_check(server, qname, qtype, rcode="NOERROR", ticket_no=1, Ortt=False):
    cmdline = [str(SCRIPT), "--qname", str(qname), "--qtype", str(qtype),
               "--port", str(server.quic_port), str(server.addr),
               "--ticket", os.path.join(t.out_dir, f"ticket{ticket_no}")]
    res = subprocess.run(cmdline, capture_output=True, text=True)

    with open(os.path.join(t.out_dir, "quic_client.out"), "a") as outf:
        outf.write("\n" + ' '.join(cmdline) + res.stdout)
    with open(os.path.join(t.out_dir, "quic_client.err"), "a") as errf:
        errf.write(res.stderr)

    isset(res.stdout.count("Received TLS session ticket") == 1, "ticket count")
    isset(res.stdout.count(f"rcode {rcode}") == 1, f"rcode {rcode}")
    if Ortt:
        isset(res.stdout.count("[+] TLS SESSION RESUMPTION: YES") == 1, "resumption used")
        isset(res.stdout.count("[+] 0-RTT ACCEPTED") == 1, "0-RTT used")
    else:
        isset(res.stdout.count("[!] TLS SESSION RESUMPTION: NO") == 1, "no resumption")
        isset(res.stdout.count("[+] 0-RTT ACCEPTED") == 0, "no 0-RTT")

t = Test(quic=True, tsig=False)

master = t.server("knot")
zone = t.zone("example.com.")
t.link(zone, master)

t.start()

master.zone_wait(zone)

tcpdump_pcap = t.out_dir + "/traffic.pcap"
tcpdump_fout = t.out_dir + "/tcpdump.out"
tcpdump_ferr = t.out_dir + "/tcpdump.err"

tcpdump_proc = subprocess.Popen(["tcpdump", "-i", "lo", "-w", tcpdump_pcap,
                                 "port", str(master.quic_port)],
                                stdout=open(tcpdump_fout, mode="a"),
                                stderr=open(tcpdump_ferr, mode="a"))

try:
    # A simple query, which is allowed as early data.
    resp_check(master, "example.com", "SOA", ticket_no=1)
    resp_check(master, "example.com", "SOA", ticket_no=1, Ortt=True)

    # An AXFR query, which is not allowed as early data for authorized operations.
    resp_check(master, "example.com", "AXFR", ticket_no=2)
    isset(master.log_search_count(r'ACL, allowed.*QUIC$') == 1, "QUIC in ACL log")
    isset(master.log_search_count(r'ACL, denied.*QUIC/0-RTT') == 0, "QUIC/0-RTT in ACL log")
    resp_check(master, "example.com", "AXFR", ticket_no=2, Ortt=True, rcode="NOTAUTH")
    isset(master.log_search_count(r'ACL, allowed.*QUIC$') == 1, "QUIC in ACL log")
    isset(master.log_search_count(r'ACL, denied.*QUIC/0-RTT') == 1, "QUIC/0-RTT in ACL log")
finally:
    tcpdump_proc.terminate()

t.end()
