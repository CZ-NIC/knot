#!/usr/bin/env python3

import binascii
import dns.name
import collections
import itertools

from dnstest.utils import *

class Response(object):
    '''Dig output context.'''

    def __init__(self, server, response, query, args):
        self.resp = response
        self.query = query
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
            if flag == "Z":
                flag_val = 64
            else:
                flag_val = dns.flags.from_text(flag)
            isset(self.resp.flags & flag_val, "%s FLAG" % flag)

        flag_names = noflags.split()
        for flag in flag_names:
            if flag == "Z":
                flag_val = 64
            else:
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

    def _check_rr(self, expect, section=None, rname=None, rtype=None):
        """
        Check for a presence of a RR with given name and type.
        """
        if section is None:
            section = "answer"
        if rname is not None:
            rname = dns.name.from_text(rname)
        if rtype is not None:
            rtype = dns.rdatatype.from_text(rtype)

        assert section in ["answer", "authority", "additional"]
        assert rname or rtype

        section_rrsets = getattr(self.resp, section)
        for rrset in section_rrsets:
            if rname is not None and rname != rrset.name:
                continue
            if rtype is not None and rtype != rrset.rdtype:
                continue
            found = True
            break
        else:
            found = False

        if found != expect:
            set_err("CHECK RR PRESENCE")
            check_log("ERROR: CHECK RR PRESENCE")
            detail_log("!%s RR name=%s type=%s section=%s" % (
                "Missing" if expect else "Extra",
                str(rname) if rname is not None else "",
                dns.rdatatype.to_text(rtype) if rtype is not None else "",
                section
            ))
            detail_log(SEP)

    def check_rr(self, section=None, rname=None, rtype=None):
        self._check_rr(True, section, rname, rtype)

    def check_no_rr(self, section=None, rname=None, rtype=None):
        self._check_rr(False, section, rname, rtype)

    def check_record(self, section="answer", rtype=None, ttl=None, rdata=None,
                     nordata=None):
        '''Checks given section for particular record/rdata'''

        sect = getattr(self.resp, section)
        if not rtype:
            rtype = self.rtype
        elif type(rtype) is str:
            rtype = dns.rdatatype.from_text(rtype)

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
              edns_version=None, flags="", noflags="", eflags="", noeflags=""):
        '''Flags are text strings separated by whitespace character'''

        self._check_flags(flags, noflags)
        self._check_eflags(eflags, noeflags)
        self._check_question()

        # Check EDNS version.
        edns_ver = int(edns_version) if edns_version != None else self.query.edns
        compare(edns_ver, self.resp.edns, "EDNS VERSION")

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

    def check_xfr(self, rcode="NOERROR"):
        '''Checks XFR message'''

        self.resp, iter_copy = itertools.tee(self.resp)

        # Get the first message.
        for msg in iter_copy:
            question = msg.question[0]
            compare(question.rdclass, self.rclass, "QCLASS")
            compare(question.rdtype, self.rtype, "QTYPE")

            # Check rcode.
            if type(rcode) is not str:
                rc = dns.rcode.to_text(rcode)
            else:
                rc = rcode
            compare(dns.rcode.to_text(msg.rcode()), rc, "RCODE")

            # Check the first message only.
            break

    # Checks whether the transfer is an AXFR-style IXFR
    def check_axfr_style_ixfr(self, axfr=None):
        # 1) QTYPE == IXFR && RCODE == NOERROR
        self.check_xfr()

        # 2) Check if Answer contains AXFR data (first SOA, second non-SOA)
        rr_count = 0

        self.resp, iter_copy = itertools.tee(self.resp)
        for msg in iter_copy:
            for rrset in msg.answer:
                for rr in rrset:
                    if rr_count == 0:
                        if rr.rdtype != dns.rdatatype.SOA:
                            set_err("First RR is not SOA")
                            return
                    elif rr_count == 1:
                        if rr.rdtype == dns.rdatatype.SOA:
                            set_err("Second RR is SOA")
                            return

                    rr_count += 1

        # 3) Check that number of records in IXFR and AXFR is the same
        if axfr:
            compare(self.count("ANY"), axfr.count("ANY"),
                    "Count of RRs in Answer")

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
             additional=False):
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
            additional=False):
        '''
        Asks server for the same question an compares specified sections

        The Additional section is not compared by default.
        '''

        resp = server.dig(**self.args)
        self.diff(resp, flags, answer, authority, additional)

    def count(self, rtype=None, section="answer"):
        '''Returns number of records of given type in specified section'''

        if not rtype:
            rtype = self.rtype
        elif type(rtype) is str:
            rtype = dns.rdatatype.from_text(rtype)

        cnt = 0
        if isinstance(self.resp, collections.Iterable):
            self.resp, iter_copy = itertools.tee(self.resp)
            for msg in iter_copy:
                if not section or section == "answer":
                    sect = msg.answer
                elif section == "additional":
                    sect = msg.additional
                elif section == "authority":
                    sect = msg.authority

                for rrset in sect:
                    if rrset.rdtype == rtype or rtype == dns.rdatatype.ANY:
                        cnt += len(rrset)
        else:
            if not section or section == "answer":
                sect = self.resp.answer
            elif section == "additional":
                sect = self.resp.additional
            elif section == "authority":
                sect = self.resp.authority

            for rrset in sect:
                if rrset.rdtype == rtype or rtype == dns.rdatatype.ANY:
                    cnt += len(rrset)

        return cnt

    def check_count(self, expected, rtype=None, section="answer"):
        found = self.count(rtype, section)
        if found != expected:
            set_err("CHECK RR COUNT")
            check_log("ERROR: CHECK RR COUNT")
            detail_log("!Invalid RR count type=%s section=%s" % (
                rtype if rtype is not None else "",
                section
            ))
            detail_log(SEP)

    def check_empty(self, section="answer"):
        self.check_count(0, None, section)

    def msg_count(self):
        '''Returns number of response messages'''

        cnt = 0
        self.resp, iter_copy = itertools.tee(self.resp)
        for msg in iter_copy:
            cnt += 1

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

    def query_size(self):
        '''Return query size.'''

        return len(self.query.to_wire())

    def response_size(self):
        '''Return response size.'''

        return len(self.resp.to_wire())
