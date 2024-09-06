#!/usr/bin/env python3

import dns.query
import dns.update
import random
import ssl

from dnstest.utils import *
from dnstest.knsupdate import Knsupdate

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

    def prereq_nx(self, owner, *args):
        self.upd.absent(owner, *args)

    def send(self, rcode="NOERROR", proto=None):
        if type(rcode) is not str and rcode is not None:
            rc = dns.rcode.to_text(rcode)
        else:
            rc = rcode

        if proto is None and self.server.tls_port and self.server.quic_port and not self.server.xdp_port:
            if type(self.upd) is Knsupdate:
                proto = random.choice([ Proto.TCP, Proto.TLS, Proto.QUIC ])
            else:
                proto = random.choice([ Proto.TCP, Proto.TLS ])
        elif proto is None:
            proto = Proto.TCP

        check_log("UPDATE over %s using %s" % (proto, "knsupdate" if type(self.upd) is Knsupdate else "dnspython"))
        detail_log(str(self.upd))
        detail_log(SEP)

        if proto == Proto.TLS:
            port = self.server.tls_port
        elif proto == Proto.QUIC:
            port = self.server.quic_port
        else:
            port = self.server.port

        if type(self.upd) is Knsupdate:
            self.rc = self.upd.send(self.server.addr, port=port, proto=proto)
        else:
            if proto == Proto.UDP:
                resp = dns.query.udp(self.upd, self.server.addr, port=port)
            elif proto == Proto.TCP:
                resp = dns.query.tcp(self.upd, self.server.addr, port=port)
            elif proto == Proto.TLS:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.VerifyMode(0)
                resp = dns.query.tls(self.upd, self.server.addr, port=port, ssl_context=ctx)
            else:
                raise Failed("DDNS-over-QUIC not supported")

            self.rc = dns.rcode.to_text(resp.rcode())

        if rc is not None:
            compare(self.rc, rc, "UPDATE RCODE")

        if type(self.upd) is not Knsupdate:
            if self.upd.keyring and self.rc != "NOTAUTH" and not resp.had_tsig:
                set_err("INVALID RESPONSE")
                check_log("ERROR: Expected TSIG signed response")

    def try_send(self):
        check_log("UPDATE")
        detail_log(str(self.upd))
        detail_log(SEP)

        if type(self.upd) is Knsupdate:
            rc = self.upd.send(self.server.addr, self.server.port, Proto.TCP)
        else:
            resp = dns.query.tcp(self.upd, self.server.addr, port=self.server.port)
            rc = dns.rcode.to_text(resp.rcode())

        check_log("RCODE")
        detail_log(rc)
        detail_log(SEP)

        return rc

    def query_size(self):
        '''Return update query size.'''

        return len(self.upd.to_wire())
