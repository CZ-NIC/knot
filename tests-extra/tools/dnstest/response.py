#!/usr/bin/env python3

import binascii
import dns.name

from dnstest.utils import *

class Response(object):
    '''Dig output context.'''

    def __init__(self, server, response, args):
        self.resp = response
        self.args = args
        self.srv = server

        self.rname = dns.name.from_text(self.args["rname"])

        if type(self.args["rtype"]) is str:
            self.rtype = dns.rdatatype.from_text(self.args["rtype"])
        else:
            self.rtype = self.args["rtype"]

        if type(self.args["rclass"]) is str:
            self.rclass = dns.rdataclass.from_text(self.args["rclass"])
        else:
            self.rclass = self.args["rclass"]

    def _check_question(self):
        question = self.resp.question.pop()
        compare(question.name, self.rname, "QNAME")
        compare(question.rdclass, self.rclass, "QCLASS")
        compare(question.rdtype, self.rtype, "QTYPE")

    def _check_flags(self, flags, noflags):
        flag_names = flags.split()
        for flag in flag_names:
            flag_val = dns.flags.from_text(flag)
            isset(self.resp.flags & flag_val, "%s FLAG" % flag)

        flag_names = noflags.split()
        for flag in flag_names:
            flag_val = dns.flags.from_text(flag)
            isset(not(self.resp.flags & flag_val), "NO %s FLAG" % flag)

    def _check_eflags(self, eflags, noeflags):
        eflag_names = eflags.split()
        for flag in eflag_names:
            flag_val = dns.flags.edns_from_text(flag)
            isset(self.resp.ednsflags & flag_val, "%s FLAG" % flag)

        eflag_names = noeflags.split()
        for flag in eflag_names:
            flag_val = dns.flags.edns_from_text(flag)
            isset(not(self.resp.ednsflags & flag_val), "NO %s FLAG" % flag)

    def check(self, rdata=None, ttl=None, rcode="NOERROR", flags="",
              noflags="", eflags="", noeflags=""):
        '''Flags are text strings separated by whitespace character'''

        self._check_flags(flags, noflags)
        self._check_eflags(eflags, noeflags)
        self._check_question()

        # Check rcode.
        if type(rcode) is not str:
            rc = dns.rcode.to_text(rcode)
        else:
            rc = rcode
        compare(dns.rcode.to_text(self.resp.rcode()), rc, "RCODE")

        # Check rdata only if NOERROR.
        if rc != "NOERROR" or rdata == None:
            return

        # We work with just one rdata with TTL=0 (this TTL is not used).
        ref = list(dns.rdataset.from_text(self.rclass, self.rtype, 0, rdata))[0]

        # Check answer section if contains reference rdata.
        for data in self.resp.answer:
            for rdata in data.to_rdataset():
                # Compare Rdataset instances.
                if rdata == ref:
                    # Check CLASS.
                    compare(data.rdclass, self.rclass, "CLASS")
                    # Check TYPE.
                    compare(data.rdtype, self.rtype, "TYPE")
                    # Check TTL if specified.
                    if ttl != None:
                        compare(data.ttl, int(ttl), "TTL")
                    return
        else:
            set_err("CHECK RDATA")
            check_log("ERROR: CHECK RDATA")
            detail_log("!Missing data in ANSWER section:")
            detail_log("  %s" % ref)
            detail_log(SEP)

    def check_edns(self, nsid=None, buff_size=None):
        compare(self.resp.edns, 0, "EDNS VERSION")

        options = 1 if nsid != None else 0
        compare(len(self.resp.options), options, "NUMBER OF EDNS0 OPTIONS")

        if options > 0:
            option = list(self.resp.options)[0]
            compare(option.otype, dns.edns.NSID, "OPTION TYPE")
            if nsid[:2] == "0x":
                compare(binascii.hexlify(option.data).decode('ascii'),
                        nsid[2:], "HEX NSID")
            else:
                compare(option.data.decode('ascii'), nsid, "TXT NSID")

    def diff(self, resp, flags=True, answer=True, authority=True,
             additional=True):
        '''Compares specified response sections against another response'''

        if flags:
            compare(dns.flags.to_text(self.resp.flags),
                    dns.flags.to_text(resp.resp.flags), "FLAGS")
            compare(dns.flags.edns_to_text(self.resp.ednsflags),
                    dns.flags.edns_to_text(resp.resp.ednsflags), "EDNS FLAGS")
        if answer:
            compare_sections(self.resp.answer, self.srv.name,
                             resp.resp.answer, resp.srv.name,
                             "ANSWER")
        if authority:
            compare_sections(self.resp.authority, self.srv.name,
                             resp.resp.authority, resp.srv.name,
                             "AUTHORITY")
        if additional:
            compare_sections(self.resp.additional, self.srv.name,
                             resp.resp.additional, resp.srv.name,
                             "ADDITIONAL")

    def cmp(self, server, flags=True, answer=True, authority=True,
            additional=True):
        '''Asks server for the same question an compares specified sections'''

        resp = server.dig(**self.args)
        self.diff(resp, flags, answer, authority, additional)

    def answer_count(self, rtype=None):
        '''Returns number of records of given type in answer section'''

        if not rtype:
            rtype = self.rtype
        elif type(rtype) is str:
            rtype = dns.rdatatype.from_text(rtype)

        for rrset in self.resp.answer:
            if rrset.rdtype == rtype:
                return len(rrset)
        else:
            return 0

