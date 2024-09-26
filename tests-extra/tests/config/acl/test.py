#!/usr/bin/env python3

'''Test for ACL configuration'''

import os
import random

from dnstest.libknot import libknot
from dnstest.test import Test
from dnstest.utils import *

def set_acl(server, actions, addrs=list(), deny=False, cert_key=None, proto=None):

    ACL_ID = "acl_test"

    ctl.connect(os.path.join(server.dir, "knot.sock"))
    ctl.send_block(cmd="conf-begin")
    resp = ctl.receive_block()

    ctl.send_block(cmd="conf-unset", section="acl", identifier=ACL_ID)
    resp = ctl.receive_block()

    ctl.send_block(cmd="conf-set", section="acl", identifier=ACL_ID)
    resp = ctl.receive_block()

    for action in actions:
        ctl.send_block(cmd="conf-set", section="acl", identifier=ACL_ID, item="action", data=action)
        resp = ctl.receive_block()
    for addr in addrs:
        ctl.send_block(cmd="conf-set", section="acl", identifier=ACL_ID, item="address", data=addr)
        resp = ctl.receive_block()
    if deny:
        ctl.send_block(cmd="conf-set", section="acl", identifier=ACL_ID, item="deny", data="on")
        resp = ctl.receive_block()
    if proto:
        ctl.send_block(cmd="conf-set", section="acl", identifier=ACL_ID, item="protocol", data=proto)
        resp = ctl.receive_block()
    if cert_key:
        ctl.send_block(cmd="conf-set", section="acl", identifier=ACL_ID, item="cert-key", data=cert_key)
        resp = ctl.receive_block()

    ctl.send_block(cmd="conf-commit")
    resp = ctl.receive_block()

    '''
    ctl.send_block(cmd="conf-read")
    resp = ctl.receive_block()
    print(resp)
    '''

    ctl.send(libknot.control.KnotCtlType.END)
    ctl.close()

def send_upd(server, zone, proto, rcode="NOERROR"):

    up = server.update(zone)
    up.add("test", 3600, "A", "1.2.3.4")
    up.send(rcode, proto=proto)

t = Test(quic=True, tls=True, tsig=False)

master = t.server("knot")
zones = t.zone_rnd(1, records=5, dnssec=False)
zones[0].name = zones[0].name.lower()
zone = zones[0]
ZONE = zones[0].name

t.link(zones, master)

ctl = libknot.control.KnotCtl()

t.start()

master.zones_wait(zones)

set_acl(master, [])

resp = master.dig(ZONE, "SOA")
resp.check(rcode="NOERROR")

resp = master.dig(ZONE, "AXFR")
resp.check_xfr(rcode="NOTAUTH")

resp = master.dig(ZONE, "NOTIFY")
resp.check(rcode="NOTAUTH")

set_acl(master, ["notify"])
resp = master.dig(ZONE, "AXFR")
resp.check_xfr(rcode="NOTAUTH")
resp = master.dig(ZONE, "NOTIFY")
resp.check(rcode="NOERROR")

set_acl(master, ["notify", "transfer"])
resp = master.dig(ZONE, "AXFR")
resp.check_xfr(rcode="NOERROR")
resp = master.dig(ZONE, "NOTIFY")
resp.check(rcode="NOERROR")

set_acl(master, ["notify"], deny=True)
resp = master.dig(ZONE, "NOTIFY")
resp.check(rcode="NOTAUTH")

set_acl(master, ["notify"], deny=True, proto="tcp")
resp = master.dig(ZONE, "NOTIFY", udp=False)
resp.check(rcode="NOTAUTH")
send_upd(master, zone, Proto.TLS, "NOTAUTH")

set_acl(master, ["update"], proto="tls")
send_upd(master, zone, Proto.UDP, "NOTAUTH")
send_upd(master, zone, Proto.TCP, "NOTAUTH")
send_upd(master, zone, Proto.TLS, "NOERROR")

t.end()
