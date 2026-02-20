#!/usr/bin/env python3

''' Check 'dnserr' query module responses. '''

from copy import deepcopy
from dnstest.module import ModCookies, ModDnsErr
from dnstest.test import Test
from dnstest.utils import *

import dns
import random

# Backward compatibility
if not hasattr(dns.edns, "ReportChannelOption"):
    ReportChannelCode = 18

    class ReportChannelOption(dns.edns.Option):
        def __init__(self, agent_domain):
            super().__init__(ReportChannelCode)
            self.agent_domain = agent_domain

        def to_wire(self, file):
            return self.agent_domain.to_wire(file)

        def to_text(self):
            return "REPORTCHANNEL " + self.agent_domain.to_text()

        @classmethod
        def from_wire_parser(cls, otype, parser):
            return cls(parser.get_name())

    dns.edns.register_type(ReportChannelOption, ReportChannelCode)

RTYPE_LIST = list(dns.rdatatype.RdataType)
RTYPE_LIST.remove(dns.rdatatype.RdataType.TYPE0)

ERROR_LIST = list(dns.edns.EDECode)
ERROR_LIST.remove(dns.edns.EDECode.OTHER)

def check_reportchannel(resp, val : str, msg : str):
    if resp == None or resp.resp == None or resp.resp.opt == None:
        set_err("CHECK \'%s\'" % msg)
        check_log("ERROR: CHECK \'%s\'" % msg)
        detail_log("  Unable to find \'%s\' in response" % val)
        detail_log(SEP)
        return True

    for i in resp.resp.opt.items:
        for o in i.options:
            if (isinstance(o, dns.edns.ReportChannelOption)):
                if val == str(o.agent_domain):
                    return False

    set_err("CHECK \'%s\'" % msg)
    check_log("ERROR: CHECK \'%s\'" % msg)
    detail_log("  Unable to find \'%s\' in response" % val)
    detail_log(SEP)
    return True

def generate_report_domain_prefix(domains : list):
    rtype_cnt = random.randint(1, 3)
    rtype_pick = [str(int(rt)) for rt in set(random.choices(RTYPE_LIST, k=rtype_cnt))]
    random.shuffle(rtype_pick)
    rtype_str = "-".join(rtype_pick)

    domain = random.choice(domains)

    edec_str = str(int(random.choice(ERROR_LIST)))

    return ('_er', rtype_str, domain.removesuffix('.') , edec_str, '_er')

REPORTCHANNEL = "agent-domain.com."

t = Test()

ModDnsErr.check()
ModCookies.check()

# Initialize server configuration
knot = t.server("knot")
zone = t.zone("example.net.", storage=".") + t.zone(REPORTCHANNEL, storage=".")
t.link(zone, knot)

knot.add_module(zone[0], ModDnsErr(report_channel=REPORTCHANNEL))
knot.add_module(zone[1], ModCookies(badcookie_slip=10))
knot.add_module(zone[1], ModDnsErr(log_report_channel=True, log_cache_size=2000, log_timeout=2))

t.start()

# Testing return of Report-Channel in normal query responses
## Try a query without EDNS
resp = knot.dig("dns1.example.net.", "A", edns=None)
resp.check(rcode="NOERROR")
compare(resp.resp.opt == None, True, "Returns Report-Channel in query without EDNS")

## Try a query with EDNS
resp = knot.dig("dns1.example.net.", "A", edns=0)
resp.check(rcode="NOERROR")
check_reportchannel(resp, REPORTCHANNEL, "Missing Report-Channel in query without EDNS")

# Testing error reporting
## Generate few positive report domains
for it in range(10):
    right_tuple = generate_report_domain_prefix(["dns1.example.net."])
    right_format = ".".join(right_tuple)

    # UDP no cookie
    resp = knot.dig(f"{right_format}.{REPORTCHANNEL}", "TXT", udp=True, edns=0)
    # TODO better test of cookie
    resp.check(rcode="NXDOMAIN")

    # TCP
    resp = knot.dig(f"{right_format}.{REPORTCHANNEL}", "TXT", udp=False, edns=0)
    resp.check(rcode="NOERROR")

    # TCP wrong RTYPE
    resp = knot.dig(f"{right_format}.{REPORTCHANNEL}", "A", udp=False, edns=0)
    resp.check(rcode="NXDOMAIN")

t.end()
