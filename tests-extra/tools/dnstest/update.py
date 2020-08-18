#!/usr/bin/env python3

import dns.query
import dns.update

from dnstest.utils import *

class Update(object):
    '''DNS update context'''

    def __init__(self, server, upd):
        self.server = server
        self.upd = upd
        self.rc = None

    def add(self, owner, ttl, rtype, rdata):
        self.upd.add(owner, ttl, rtype, rdata)

    def delete(self, owner, *args):
        self.upd.delete(owner, *args)

    def prereq_yx(self, owner, *args):
        self.upd.present(owner, *args)

    def prereq_nx(self, owner, rtype=None):
        self.upd.absent(owner, rtype)

    def send(self, rcode="NOERROR"):

        if type(rcode) is not str and rcode is not None:
            rc = dns.rcode.to_text(rcode)
        else:
            rc = rcode

        check_log("UPDATE")
        detail_log(str(self.upd))
        detail_log(SEP)

        resp = dns.query.tcp(self.upd, self.server.addr, port=self.server.port)
        self.rc = dns.rcode.to_text(resp.rcode())
        if rc is not None:
            compare(self.rc, rc, "UPDATE RCODE")

        if self.upd.keyring and not resp.had_tsig:
            set_err("INVALID RESPONSE")
            check_log("ERROR: Expected TSIG signed response")

    def try_send(self):
        check_log("UPDATE")
        detail_log(str(self.upd))
        detail_log(SEP)

        resp = dns.query.tcp(self.upd, self.server.addr, port=self.server.port)
        check_log("RCODE")
        detail_log(dns.rcode.to_text(resp.rcode()))
        detail_log(SEP)

        return dns.rcode.to_text(resp.rcode())

    def query_size(self):
        '''Return update query size.'''

        return len(self.upd.to_wire())
