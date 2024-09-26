#!/usr/bin/env python3

'''Test for ACL configuration'''

import os
import random

from dnstest.libknot import libknot
from dnstest.test import Test
from dnstest.utils import *

RMT = random.choice([False, True])
detail_log("ACL remote %s" % (str(RMT)))

RMT_ID = "rmt_test"
ACL_ID = "acl_test"

def set_remote(addrs=list(), protos=list(), cert_key=None):

    try:
        ctl.send_block(cmd="conf-unset", section="remote", identifier=RMT_ID)
        resp = ctl.receive_block()
    except:
        pass

    ctl.send_block(cmd="conf-set", section="remote", identifier=RMT_ID)
    resp = ctl.receive_block()

    for addr in addrs:
        ctl.send_block(cmd="conf-set", section="remote", identifier=RMT_ID, item="address", data=addr)
        resp = ctl.receive_block()
    for proto in protos:
        if proto == "quic":
            ctl.send_block(cmd="conf-set", section="remote", identifier=RMT_ID, item="quic", data="on")
            resp = ctl.receive_block()
        if proto == "tls":
            ctl.send_block(cmd="conf-set", section="remote", identifier=RMT_ID, item="tls", data="on")
            resp = ctl.receive_block()
    if cert_key:
        ctl.send_block(cmd="conf-set", section="remote", identifier=RMT_ID, item="cert-key", data=cert_key)
        resp = ctl.receive_block()

def set_autoacl(server, zone, item, addrs=list(), protos=list(), cert_key=None):

    ZONE = zone.name

    ctl.connect(os.path.join(server.dir, "knot.sock"))
    ctl.send_block(cmd="conf-begin")
    resp = ctl.receive_block()

    ctl.send_block(cmd="conf-set", section="server", item="automatic-acl", data="on")
    resp = ctl.receive_block()

    if not addrs:
        addrs = [server.addr]
    set_remote(addrs, protos, cert_key)
    ctl.send_block(cmd="conf-set", section="zone", identifier=ZONE, item=item, data=RMT_ID)
    resp = ctl.receive_block()

    try:
        ctl.send_block(cmd="conf-unset", section="zone", identifier=ZONE, item="acl")
        resp = ctl.receive_block()
    except:
        pass

    ctl.send_block(cmd="conf-commit")
    resp = ctl.receive_block()

    ctl.send(libknot.control.KnotCtlType.END)
    ctl.close()

def set_acl(server, actions, deny=False, addrs=list(), protos=list(), cert_key=None):

    ctl.connect(os.path.join(server.dir, "knot.sock"))
    ctl.send_block(cmd="conf-begin")
    resp = ctl.receive_block()

    try:
        ctl.send_block(cmd="conf-unset", section="acl", identifier=ACL_ID)
        resp = ctl.receive_block()
    except:
        pass

    ctl.send_block(cmd="conf-set", section="acl", identifier=ACL_ID)
    resp = ctl.receive_block()

    for action in actions:
        ctl.send_block(cmd="conf-set", section="acl", identifier=ACL_ID, item="action", data=action)
        resp = ctl.receive_block()
    if deny:
        ctl.send_block(cmd="conf-set", section="acl", identifier=ACL_ID, item="deny", data="on")
        resp = ctl.receive_block()

    if RMT:
        if not addrs:
            addrs = [server.addr]
        set_remote(addrs, protos, cert_key)
        ctl.send_block(cmd="conf-set", section="acl", identifier=ACL_ID, item="remote", data=RMT_ID)
        resp = ctl.receive_block()
    else:
        for addr in addrs:
            ctl.send_block(cmd="conf-set", section="acl", identifier=ACL_ID, item="address", data=addr)
            resp = ctl.receive_block()
        for proto in protos:
            ctl.send_block(cmd="conf-set", section="acl", identifier=ACL_ID, item="protocol", data=proto)
            resp = ctl.receive_block()
        if cert_key:
            ctl.send_block(cmd="conf-set", section="acl", identifier=ACL_ID, item="cert-key", data=cert_key)
            resp = ctl.receive_block()

    ctl.send_block(cmd="conf-commit")
    resp = ctl.receive_block()

    ctl.send(libknot.control.KnotCtlType.END)
    ctl.close()

def send_upd(server, zone, rcode="NOERROR", proto=Proto.TCP):

    up = server.update(zone)
    up.add("test", 3600, "A", "1.2.3.4")
    up.send(rcode, proto=proto)

def test_normal(server, zone):

    ZONE = zone.name

    # Purge the ACL rule.
    set_acl(server, [])

    # Normal queries don't require authorization.
    resp = server.dig(ZONE, "SOA")
    resp.check(rcode="NOERROR")

    # Authorized operations are denied by default.
    resp = server.dig(ZONE, "NOTIFY")
    resp.check(rcode="NOTAUTH")
    resp = server.dig(ZONE, "AXFR")
    resp.check_xfr(rcode="NOTAUTH")

    # Authorize only one action.
    set_acl(server, ["notify"])
    resp = server.dig(ZONE, "NOTIFY")
    resp.check(rcode="NOERROR")
    resp = server.dig(ZONE, "AXFR")
    resp.check_xfr(rcode="NOTAUTH")

    # Authorize more actions.
    set_acl(server, ["notify", "transfer"])
    resp = server.dig(ZONE, "NOTIFY")
    resp.check(rcode="NOERROR")
    resp = server.dig(ZONE, "AXFR")
    resp.check_xfr(rcode="NOERROR")
    send_upd(server, zone, "NOTAUTH")

    # Deny explicit action.
    set_acl(server, ["notify"], deny=True)
    resp = server.dig(ZONE, "NOTIFY")
    resp.check(rcode="NOTAUTH")

    # Authorize only some protocols.
    set_acl(server, ["update"], addrs=[t.addr], protos=["tls", "udp"])
    send_upd(server, zone, "NOTAUTH", Proto.TCP)
    send_upd(server, zone, "NOERROR", Proto.TLS)
    if not RMT: # Remote doesn't distinguish between UDP and TCP.
        send_upd(server, zone, "NOERROR", Proto.UDP)

    # Authorize different address and protocol.
    set_acl(server, ["update"], addrs=["192.0.2.1"], protos=["tls", "udp"])
    send_upd(server, zone, "NOTAUTH", Proto.TLS)
    send_upd(server, zone, "NOTAUTH", Proto.TCP)


    # Automatic ACL for XFR.
    set_autoacl(server, zone, "notify", protos=["tcp"])
    resp = server.dig(ZONE, "AXFR")
    resp.check_xfr(rcode="NOERROR")

    # Automatic ACL for XFR bad proto.
    set_autoacl(server, zone, "notify", protos=["tls"])
    resp = server.dig(ZONE, "AXFR")
    resp.check_xfr(rcode="NOTAUTH")

    # Automatic ACL for NOTIFY.
    set_autoacl(server, zone, "master", protos=["tcp"])
    resp = server.dig(ZONE, "NOTIFY")
    resp.check(rcode="NOERROR")

    # Automatic ACL for NOTIFY bad proto.
    set_autoacl(server, zone, "master", protos=["quic"])
    resp = server.dig(ZONE, "NOTIFY")
    resp.check(rcode="NOTAUTH")

t = Test(quic=True, tls=True, tsig=False)

master = t.server("knot")
zones = t.zone_rnd(1, records=5, dnssec=False)
zones[0].name = zones[0].name.lower()
t.link(zones, master)

ctl = libknot.control.KnotCtl()

t.start()

master.zones_wait(zones)

test_normal(master, zones[0])

t.end()
