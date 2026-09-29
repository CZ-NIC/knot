#!/usr/bin/env python3

'''Check 'ecs' query module functionality.'''

import dns.edns
from dnstest.test import Test
from dnstest.module import ModEcs
from dnstest.utils import *

def ecs_scope(resp):
    for opt in resp.resp.options:
        if opt.otype == dns.edns.ECS:
            return opt.scopelen
    return None

t = Test()

ModEcs.check()

knot = t.server("knot")
scoped = t.zone("example.com.", storage=".")
plain = t.zone("noecs.example.com.", storage=".")

t.link(scoped + plain, knot)

knot.conf_srv().edns_client_subnet = True
knot.add_module(scoped, ModEcs())

t.start()
knot.zones_wait(scoped + plain)

resp = knot.dig("example.com.", "A", ecs=("192.0.2.0", 24))
resp.check(rcode="NOERROR")
compare(ecs_scope(resp), 24, "scope on positive answer")

resp = knot.dig("nonexistent.example.com.", "A", ecs=("192.0.2.0", 24))
resp.check(rcode="NXDOMAIN")
compare(ecs_scope(resp), 24, "scope on NXDOMAIN")

resp = knot.dig("example.com.", "MX", ecs=("192.0.2.0", 24))
resp.check(rcode="NOERROR")
compare(resp.count(), 0, "MX count")
compare(ecs_scope(resp), 24, "scope on NODATA")

resp = knot.dig("www.sub.example.com.", "A", ecs=("192.0.2.0", 24))
resp.check_count(0, "SOA", section="authority")
resp.check_count(1, "NS", section="authority")
compare(ecs_scope(resp), 24, "scope on referral")

resp = knot.dig("example.com.", "A", ecs=("0.0.0.0", 0))
resp.check(rcode="NOERROR")
compare(ecs_scope(resp), 0, "zero source yields zero scope")

resp = knot.dig("example.com.", "A", ecs=("2001:db8::", 56))
resp.check(rcode="NOERROR")
compare(ecs_scope(resp), 56, "scope for IPv6 client subnet")

resp = knot.dig("noecs.example.com.", "A", ecs=("192.0.2.0", 24))
resp.check(rcode="NOERROR")
compare(ecs_scope(resp), 0, "scope untouched without the module")

knot.conf_srv().edns_client_subnet = False
knot.gen_confile()
knot.reload()

resp = knot.dig("example.com.", "A", ecs=("192.0.2.0", 24))
resp.check(rcode="NOERROR")
compare(ecs_scope(resp), None, "no ECS option with the feature off")

t.end()
