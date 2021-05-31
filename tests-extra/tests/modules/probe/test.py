#!/usr/bin/env python3

'''Test for the probe module'''

import dns.rdatatype

from dnstest.utils import *
from dnstest.test import Test
from dnstest.module import ModProbe
from dnstest.libknot import libknot

class TestItem(object):
    def __init__(self, qname: str, qtype: str, udp: bool, dnssec: bool, rcode: str,
            ede: int = libknot.probe.KnotProbeData.EDE_NONE, aa: bool = False, nsid: bool = False):
        self.qname = qname
        self.qtype = qtype
        self.udp = udp
        self.dnssec = dnssec
        self.rcode = rcode
        self.ede = ede
        self.aa = aa
        self.nsid = nsid

    def check(self, data, server):
        compare(data.ip, 6 if ":" in server.addr else 4, "IP version")
        ref_proto = libknot.probe.KnotProbeDataProto.UDP if self.udp else \
                    libknot.probe.KnotProbeDataProto.TCP
        compare(data.proto, ref_proto.value, "proto")
        compare(data.addr_str(data.local_addr), server.addr, "local address")
        compare(data.local_port, server.port, "local port")

        compare(data.qname_str(), str(dns.name.from_text(self.qname)), "qname")
        compare(data.query_type, dns.rdatatype.from_text(self.qtype), "qtype")
        compare(data.query_class, 1, "qclass")

        ref_edns = self.dnssec or self.nsid
        compare(bool(data.edns_present), ref_edns, "EDNS")
        if ref_edns:
            compare(data.edns_version, 0, "EDNS version")
        compare(data.edns_options, 8 if self.nsid else 0, "NSID")
        compare(bool(data.edns_flag_do), self.dnssec, "DO")

        ref_rcode = dns.rcode.from_text(self.rcode)
        compare(data.reply_rcode, ref_rcode, "rcode")
        compare(data.reply_ede, self.ede, "EDE")

        compare(data.reply_hdr.id, data.query_hdr.id, "header ID match")
        compare(bool(data.reply_hdr.flag_qr), True, "reply QR")
        compare(bool(data.query_hdr.flag_qr), False, "query QR")
        compare(data.reply_hdr.opcode, 0, "reply OPCODE")
        compare(data.query_hdr.opcode, 0, "query OPCODE")
        compare(bool(data.reply_hdr.flag_aa), self.aa, "reply AA")
        compare(data.reply_hdr.rcode, ref_rcode, "reply RCODE")
        compare(data.reply_hdr.questions, 1, "reply questions")
        compare(data.query_hdr.questions, 1, "query questions")

tests = [TestItem("ns1.example.", "A", udp=True, dnssec=False, rcode="NOERROR", aa=True),
         TestItem("not-exists.example.", "A", udp=False, dnssec=True, rcode="NXDOMAIN", aa=True),
         TestItem("example.", "SOA", udp=True, dnssec=True, rcode="NOERROR", aa=True, nsid=True),
         TestItem(".", "SOA", udp=True, dnssec=False, rcode="REFUSED"),
         TestItem(".", "SOA", udp=True, dnssec=True, rcode="REFUSED", ede=20)]

t = Test(stress=False, tsig=False)

ModProbe.check()

server = t.server("knot")
zone = t.zone("example.")
t.link(zone, server)
server.add_module(None, ModProbe(t.out_dir, channels=1))

probe = libknot.probe.KnotProbe(t.out_dir, idx=1)
data = libknot.probe.KnotProbeDataArray()

t.start()

t.sleep(1) # Not zone_wait() as it would generate probe data!

for item in tests:
    resp = server.dig(item.qname, item.qtype, udp=item.udp, dnssec=item.dnssec, nsid=item.nsid)
    probe.consume(data)
    compare(data.used, 1, "data array occupation")
    item.check(data[0], server)

t.end()
