#!/usr/bin/env python3

import binascii
import dns.name

from dnstest.utils import *

class Response(object):
    '''Dig output context'''

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
        compare(question.name, self.rname, "question.name")
        compare(question.rdclass, self.rclass, "question.class")
        compare(question.rdtype, self.rtype, "question.type")

    def _check_flags(self, flags, noflags):
        flag_names = flags.split()
        for flag in flag_names:
            flag_val = dns.flags.from_text(flag)
            isset(self.resp.flags & flag_val, "%s flag" % flag)

        flag_names = noflags.split()
        for flag in flag_names:
            flag_val = dns.flags.from_text(flag)
            isset(not(self.resp.flags & flag_val), "no %s flag" % flag)

    def check(self, rdata=None, ttl=None, rcode="NOERROR", flags="", \
              noflags=""):
        '''Flags are text strings separated by whitespace character'''

        self._check_flags(flags, noflags)
        self._check_question()

        # Check rcode.
        if type(rcode) is str:
            rc = dns.rcode.from_text(rcode)
        else:
            rc = rcode
        compare(self.resp.rcode(), rc, "RCODE")

        # Check rdata only if NOERROR.
        if rc != 0 or rdata == None:
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
            err("RDATA (" + str(rdata) + ") not in ANSWER section")
            set_err("CHECK rdata")

    def check_edns(self, nsid=None, buff_size=None):
        compare(self.resp.edns, 0, "EDNS version")

        options = 1 if nsid != None else 0
        compare(len(self.resp.options), options, "number of EDNS0 options")

        if options > 0:
            option = list(self.resp.options)[0]
            compare(option.otype, dns.edns.NSID, "option type")
            if nsid[:2] == "0x":
                compare(binascii.hexlify(option.data).decode('ascii'), \
                        nsid[2:], "hex NSID")
            else:
                compare(option.data.decode('ascii'), nsid, "txt NSID")

    def diff(self, resp, flags=True, answer=True, authority=True, \
             additional=False):
        '''Compares specified response sections against another response'''

        if flags:
            compare(dns.flags.to_text(self.resp.flags), \
                    dns.flags.to_text(resp.resp.flags), "FLAGS")
            compare(dns.flags.edns_to_text(self.resp.ednsflags), \
                    dns.flags.edns_to_text(resp.resp.ednsflags), "EDNS FLAGS")
        if answer:
            compare_sections(self.resp.answer, self.srv.name, \
                             resp.resp.answer, resp.srv.name, \
                             "ANSWER")
        if authority:
            compare_sections(self.resp.answer, self.srv.name, \
                             resp.resp.answer, resp.srv.name, \
                             "AUTHORITY")
        if additional:
            compare_sections(self.resp.answer, self.srv.name, \
                             resp.resp.answer, resp.srv.name, \
                             "ADDITIONAL")

    def cmp(self, server, flags=True, answer=True, authority=True, \
            additional=False):
        '''Asks server for the same question an compares specified sections'''

        resp = server.dig(**self.args)
        self.diff(resp, flags, answer, authority, additional)
