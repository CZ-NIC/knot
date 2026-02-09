#!/usr/bin/env python3

''' Check DNS Error Reporting module. '''

import dns
from dnstest.module import ModDnsErr
from dnstest.test import Test
from dnstest.utils import *

# Backward compatibility
if not hasattr(dns.edns, "ReportChannelOption"):
    ReportChannelCode = 18

    class ReportChannelOption(dns.edns.Option):
        def __init__(self, agent_domain):
            super().__init__(ReportChannelCode)
            self.agent_domain = agent_domain

        def to_wire(self):
            return self.agent_domain.to_wire()

        def to_text(self):
            return "REPORTCHANNEL " + self.agent_domain.to_text()

        @classmethod
        def from_wire_parser(cls, otype, parser):
            return cls(parser.get_name())

    dns.edns.register_type(ReportChannelOption, ReportChannelCode)
    dns.edns.ReportChannelOption = ReportChannelOption

class ErrReport():
    def __init__(self, zone, owner, rtype_txt, error_code):
        self.zone = zone
        self.owner = owner
        self.rtype_txt = rtype_txt
        self.error_code = error_code

    def query(self):
        rtype = dns.rdatatype.from_text(self.rtype_txt)
        return f"_er.{rtype}.{self.owner}.{self.error_code}._er.{self.zone}"

def check_channel(resp, val):
    if resp == None or resp.resp == None or resp.resp.opt == None:
        return False

    for i in resp.resp.opt.items:
        for o in i.options:
            if (isinstance(o, dns.edns.ReportChannelOption)):
                detail_log("Received EDNS ReportChannel \'%s\'" % o.agent_domain)
                if val == str(o.agent_domain):
                    return True

    return False

def check_report(server, report, count):
    pattern = f"report, qname '{report.owner}.', qtype {report.rtype_txt}, error {report.error_code}"
    found = server.log_search_count(pattern)
    if found != count:
        detail_log("LOG SEARCH COUNT '%s' found %d expected %d" % (pattern, found, count))
        set_err("LOG SEARCH COUNT %d != %d" % (found, count))

t = Test()

ModDnsErr.check()

CHANNEL = "channel.example."
agent = t.server("knot")
zone_channel = t.zone_rnd(1, names=[CHANNEL])
t.link(zone_channel, agent)
agent.add_module(zone_channel[0], ModDnsErr(agent=True, cache_size=3, cache_lifetime=3))

server = t.server("knot")
zone = t.zone("example.com.")
t.link(zone, server)
server.add_module(zone[0], ModDnsErr(report_channel=CHANNEL))

t.start()

server.zones_wait(zone)
agent.zones_wait(zone_channel)

## Testing return of Report-Channel in normal query responses

# Try a query without EDNS
resp = server.dig("dns1.example.com.", "A", edns=None)
resp.check(rcode="NOERROR")
isset(resp.resp.opt == None, "no EDNS Report-Channel present")

# Try a query with EDNS
resp = server.dig("dns1.example.com.", "A", edns=0)
resp.check(rcode="NOERROR")
isset(check_channel(resp, CHANNEL), "correct EDNS Report-Channel present")

## Testing agent

ERR_RESP = '"Report received"'

report1 = ErrReport(CHANNEL, "report1", "A", 2)
report2 = ErrReport(CHANNEL, "report2", "A", 2)
report3 = ErrReport(CHANNEL, "report2", "AAAA", 2)
report4 = ErrReport(CHANNEL, "report3", "AAAA", 2)

# Query the reporting zone normally
resp = agent.dig(CHANNEL, "SOA")
resp.check(rcode="NOERROR", flags="AA")

# Query with incomplete report QNAMEs
resp = agent.dig("_er." + CHANNEL, "TXT", udp=False)
resp.check(rcode="FORMERR")
resp = agent.dig("_er.1.test." + CHANNEL, "TXT", udp=False)
resp.check(rcode="FORMERR")
resp = agent.dig("_er.1.test._err." + CHANNEL, "TXT", udp=False)
resp.check(rcode="FORMERR")

# Report not accepted over UDP
resp = agent.dig(report1.query(), "TXT", udp=True)
resp.check(rcode="NOERROR", flags="AA TC")
resp.check_counts(answer=0, authority=0, additional=0)

# Report not accepted over TCP - bad QTYPE
resp = agent.dig(report1.query(), "A", udp=False)
resp.check(rcode="NXDOMAIN", flags="AA", noflags="TC")
resp.check_counts(answer=0, authority=1, additional=0)

# Report accepted over TCP
resp = agent.dig(report1.query(), "TXT", udp=False)
resp.check_record(section="answer", rtype="TXT", ttl="3", rdata=ERR_RESP)
resp.check_counts(answer=1, authority=0, additional=0)
check_report(agent, report1, 1)

# Report multiple reports over TCP - cache is fully occupied
for report in [report1, report2, report3]:
    resp = agent.dig(report.query(), "TXT", udp=False)
    resp.check_record(section="answer", rtype="TXT", ttl="3", rdata=ERR_RESP)
    resp.check_counts(answer=1, authority=0, additional=0)
    check_report(agent, report, 1)

# Report not logged due to full cache
resp = agent.dig(report4.query(), "TXT", udp=False)
resp.check_record(section="answer", rtype="TXT", ttl="3", rdata=ERR_RESP)
resp.check_counts(answer=1, authority=0, additional=0)
check_report(agent, report4, 0)

t.sleep(3)

# Repeat the report after the cache is flushed
resp = agent.dig(report4.query(), "TXT", udp=False)
resp.check_record(section="answer", rtype="TXT", ttl="3", rdata=ERR_RESP)
resp.check_counts(answer=1, authority=0, additional=0)
check_report(agent, report4, 1)

t.end()
