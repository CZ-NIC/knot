#!/usr/bin/env python3

'''Basic RRL functionality test'''

import dns.exception
import dns.message
import dns.query
import time

from dnstest.test import Test
from dnstest.utils import *

t = Test(stress=False)
knot = t.server("knot")
zone = t.zone("example.com.")
t.link(zone, knot)

def send_queries(server, run_time=1.0, query_time=0.05):
    """
    Send UDP queries to the server for certain time and get replies statistics.
    """
    replied, truncated, dropped = 0, 0, 0
    start = time.time()
    while time.time() < start + run_time:
        try:
            query = dns.message.make_query("example.com", "SOA", want_dnssec=True)
            response = dns.query.udp(query, server.addr, port=server.port, timeout=query_time)
        except dns.exception.Timeout:
            response = None

        if response is None:
            dropped += 1
        elif response.flags & dns.flags.TC:
            truncated += 1
        else:
            replied += 1

    return dict(replied=replied, truncated=truncated, dropped=dropped)

def rrl_result(name, stats, success):
    detail_log("RRL %s" % name)
    detail_log(", ".join(["%s %d" % (s, stats[s]) for s in ["replied", "truncated", "dropped"]]))
    if success:
        detail_log("success")
    else:
        detail_log("error")
        set_err("RRL ERROR")

t.start()
knot.zone_wait(zone)
t.sleep(1)

#
# We cannot send queries in parallel. And we have to give the server some time
# to respond, especially under valgrind. Therefore we have to be tolerant when
# counting responses when packets are being dropped.
#

stats = send_queries(knot)
ok = stats["replied"] >= 100 and stats["truncated"] == 0 and stats["dropped"] == 0
rrl_result("RRL disabled", stats, ok)

knot.ratelimit = 5
knot.gen_confile()
knot.reload()
stats = send_queries(knot)
ok = stats["replied"] > 0 and stats["replied"] < 100 and stats["truncated"] >= 100 and stats["dropped"] == 0
rrl_result("RRL enabled, all slips", stats, ok)
time.sleep(5)

knot.ratelimit_slip = 0
knot.gen_confile()
knot.reload()
stats = send_queries(knot)
ok = stats["replied"] > 0 and stats["replied"] < 100 and stats["truncated"] == 0 and stats["dropped"] >= 5
rrl_result("RRL enabled, no slips", stats, ok)

knot.ratelimit_slip = 2
knot.gen_confile()
knot.reload()
stats = send_queries(knot)
ok = stats["replied"] > 0 and stats["replied"] < 100 and stats["truncated"] >= 5 and stats["dropped"] >= 5
rrl_result("RRL enabled, 50% slips", stats, ok)

knot.ratelimit_whitelist = knot.addr
knot.gen_confile()
knot.reload()
stats = send_queries(knot)
ok = stats["replied"] >= 100 and stats["truncated"] == 0 and stats["dropped"] == 0
rrl_result("RRL enabled, whitelist effective", stats, ok)

t.end()
