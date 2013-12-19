#!/usr/bin/env python3

import dns.query
import dns.update

from dnstest.utils import *

class Update(object):
    '''DNS update context'''

    def __init__(self, server, upd):
        self.server = server
        self.upd = upd

    def add(self, owner, ttl, rtype, rdata):
        self.upd.add(owner, ttl, rtype, rdata)

    def delete(self, owner, *args):
        self.upd.delete(owner, *args)

    def prereq_yx(self, owner, *args):
        self.upd.present(owner, *args)

    def prereq_nx(self, owner, rtype=None):
        self.upd.absent(owner, rtype)

    def send(self, rcode="NOERROR"):
        if type(rcode) is str:
            rc = dns.rcode.from_text(rcode)
        else:
            rc = rcode

        check_log("UPDATE")
        detail_log(str(self.upd))
        detail_log(SEP)

        resp = dns.query.tcp(self.upd, self.server.addr, port=self.server.port)
        compare(resp.rcode(), rc, "update rcode")
