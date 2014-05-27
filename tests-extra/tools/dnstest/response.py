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
        question = self.resp.question[0]
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

    def check_record(self, section="answer", rtype=None, ttl=None, rdata=None,
                     nordata=None):
        '''Checks given section for particular record/rdata'''

        if not rtype:
            rtype = self.rtype
        elif type(rtype) is str:
            rtype = dns.rdatatype.from_text(rtype)

        if section == "answer":
            sect = self.resp.answer
        elif section == "additional":
            sect = self.resp.additional
        elif section == "authority":
            sect = self.resp.authority

        # Check rdata presence.
        if rdata:
            # We work with just one rdata with TTL=0 (this TTL is not used).
            rrset = dns.rdataset.from_text(self.rclass, rtype, 0, rdata)
            ref = str(list(rrset)[0])

            # Check answer section if contains reference rdata.
            for data in sect:
                for rd in data.to_rdataset():
                    # Compare Rdataset instances.
                    if str(rd) == ref:
                        # Check CLASS.
                        compare(data.rdclass, self.rclass, "CLASS")
                        # Check TYPE.
                        compare(data.rdtype, rtype, "TYPE")
                        # Check TTL if specified.
                        if ttl != None:
                            compare(data.ttl, int(ttl), "TTL")
                        return
            else:
                set_err("CHECK RDATA")
                check_log("ERROR: CHECK RDATA")
                detail_log("!Missing data in %s section:" % section)
                detail_log("  %s" % ref)
                detail_log(SEP)
        # Check rdata absence.
        if nordata:
            # We work with just one rdata with TTL=0 (this TTL is not used).
            rrset = dns.rdataset.from_text(self.rclass, rtype, 0, nordata)
            ref = str(list(rrset)[0])

            # Check answer section if contains reference rdata.
            for data in sect:
                for rd in data.to_rdataset():
                    # Compare Rdataset instances.
                    if str(rd) == ref and data.rdtype == rtype:
                        set_err("CHECK RDATA")
                        check_log("ERROR: CHECK RDATA")
                        detail_log("!Unwanted data in %s section:" % section)
                        detail_log("  %s" % ref)
                        detail_log(SEP)
                        return

    def check(self, rdata=None, ttl=None, rcode="NOERROR", nordata=None,
              flags="", noflags="", eflags="", noeflags=""):
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
        if rc == "NOERROR":
            self.check_record(section="answer", rtype=self.rtype, ttl=ttl,
                              rdata=rdata, nordata=nordata)

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

    def count(self, rtype=None, section="answer"):
        '''Returns number of records of given type in specified section'''

        if not rtype:
            rtype = self.rtype
        elif type(rtype) is str:
            rtype = dns.rdatatype.from_text(rtype)

        if not section or section == "answer":
            sect = self.resp.answer
        elif section == "additional":
            sect = self.resp.additional
        elif section == "authority":
            sect = self.resp.authority

        cnt = 0
        for rrset in sect:
            if rrset.rdtype == rtype or rtype == dns.rdatatype.ANY:
                cnt += len(rrset)

        return cnt

    def check_nsec(self, nsec3=False, nonsec=False):
        '''Checks if the response contains NSEC(3) records.'''

        nsec_rrs = list()
        nsec3_rrs = list()
        for data in self.resp.authority:
            rrset = data.to_rdataset()
            records = data.to_text().split("\n")
            if rrset.rdtype == dns.rdatatype.NSEC:
                nsec_rrs.extend(records)
            elif rrset.rdtype == dns.rdatatype.NSEC3:
                nsec3_rrs.extend(records)

        if nonsec:
            if nsec_rrs or nsec3_rrs:
                set_err("CHECK NSEC(3) ABSENCE")
                check_log("ERROR: CHECK NSEC(3) ABSENCE")
                detail_log("!Unexpected records:")
                for rr in nsec_rrs + nsec3_rrs:
                    detail_log("  %s" % rr)
                detail_log(SEP)
            return

        if nsec3:
            if not nsec3_rrs:
                set_err("CHECK NSEC3 PRESENCE")
                check_log("ERROR: CHECK NSEC3 PRESENCE")
                detail_log(SEP)
            if nsec_rrs:
                set_err("CHECK NSEC3")
                check_log("ERROR: CHECK NSEC3")
                detail_log("!Unexpected records:")
                for rr in nsec_rrs:
                    detail_log("  %s" % rr)
                detail_log(SEP)
        else:
            if not nsec_rrs:
                set_err("CHECK NSEC PRESENCE")
                check_log("ERROR: CHECK NSEC PRESENCE")
                detail_log(SEP)
            if nsec3_rrs:
                set_err("CHECK NSEC")
                check_log("ERROR: CHECK NSEC")
                detail_log("!Unexpected records:")
                for rr in nsec3_rrs:
                    detail_log("  %s" % rr)
                detail_log(SEP)
