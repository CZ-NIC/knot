#!/usr/bin/env python3

'''Basic RRL functionality test'''

import asyncio
import dns.exception
import dns.message
import dns.query

from dnstest.test import Test
from dnstest.utils import *

t = Test(stress=False)
knot = t.server("knot")
zone = t.zone("example.com.")
t.link(zone, knot)

class DNSQuery(asyncio.DatagramProtocol):
    def __init__(self, query):
        self.query = query
        self.transport = None
        self.response = asyncio.Future()

    def connection_made(self, transport):
        self.transport = transport
        query = dns.message.make_query(*self.query, want_dnssec=True)
        self.transport.sendto(query.to_wire())

    def connection_lost(self, exc):
        if exc is not None:
            self.response.set_exception(exc)

    def datagram_received(self, data, addr):
        try:
            response = dns.message.from_wire(data)
            self.response.set_result(response)
        except Exception as exc:
            self.response.set_exception(exc)

    def error_received(self, exc):
        self.response.set_exception(exc)

@asyncio.coroutine
def dns_query(loop, server, query, delay=0.0):
    endpoint = loop.create_datagram_endpoint(lambda: DNSQuery(query), remote_addr=server)
    transport = None
    try:
        yield from asyncio.sleep(delay)
        transport, protocol = yield from endpoint
        return (yield from protocol.response)
    finally:
        if transport:
            transport.abort()

@asyncio.coroutine
def run_queries(loop, server, query, count, timeout=0.5):
    """
    Send UDP queries to the server and gets reply statistics.
    """
    queries = []
    for i in range(count):
        delay = (i // 10) * 0.01
        cor = dns_query(loop, server, query, delay)
        queries.append(asyncio.wait_for(cor, delay + timeout))

    stats = dict(replied=0, truncated=0, dropped=0, errors=0)
    for query in asyncio.as_completed(queries):
        try:
            response = yield from query
            if response.flags & dns.flags.TC:
                cls = "truncated"
            else:
                cls = "replied"
        except asyncio.TimeoutError:
            cls = "dropped"
        except:
            cls = "errors"
        stats[cls] += 1
    return stats

t.start()
knot.zone_wait(zone)
t.sleep(1)

# Knot uses a 4-second "smoothing" window when computing the rate. Therefore
# the rate can be 4 times higher at times.

QUERY = ("example.com", "SOA")
COUNT = 100
TIMEOUT = 0.5
RRL = 5

def send_queries(loop, server):
    target = (server.addr, server.port)
    return loop.run_until_complete(run_queries(loop, target, QUERY, COUNT, TIMEOUT))

def rrl_result(name, stats, success):
    detail_log("RRL %s" % name)
    detail_log(", ".join(["%s %d" % (s, stats[s]) for s in ["replied", "truncated", "dropped", "errors"]]))
    if success:
        detail_log("success")
    else:
        detail_log("error")
        set_err("RRL ERROR")

loop = asyncio.get_event_loop()

stats = send_queries(loop, knot)
ok = (
    stats["replied"] == COUNT and
    stats["truncated"] == 0 and
    stats["dropped"] == 0
)
rrl_result("RRL disabled", stats, ok)

knot.ratelimit = RRL
knot.gen_confile()
knot.reload()
stats = send_queries(loop, knot)
ok = (
    RRL <= stats["replied"] <= 5 * RRL and
    stats["truncated"] == COUNT - stats["replied"] and
    stats["dropped"] == 0
)
rrl_result("RRL enabled, all slips", stats, ok)

knot.ratelimit_slip = 0
knot.gen_confile()
knot.reload()
stats = send_queries(loop, knot)
ok = (
    RRL <= stats["replied"] <= 5 * RRL and
    stats["truncated"] == 0 and
    stats["dropped"] == COUNT - stats["replied"]
)
rrl_result("RRL enabled, no slips", stats, ok)

knot.ratelimit_slip = 2
knot.gen_confile()
knot.reload()
stats = send_queries(loop, knot)
ok = (
    RRL <= stats["replied"] <= 5 * RRL and
    stats["truncated"] + stats["dropped"] == COUNT - stats["replied"] and
    -10 <= ((stats["truncated"] + stats["dropped"]) // 2 - stats["truncated"]) <= 10
)
rrl_result("RRL enabled, 50% slips", stats, ok)

knot.ratelimit_whitelist = knot.addr
knot.gen_confile()
knot.reload()
stats = send_queries(loop, knot)
ok = (
    stats["replied"] == COUNT and
    stats["truncated"] == 0 and
    stats["dropped"] == 0
)
rrl_result("RRL enabled, whitelist effective", stats, ok)

loop.close()

t.end()
