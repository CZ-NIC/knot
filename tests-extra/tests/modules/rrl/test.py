#!/usr/bin/env python3

'''RRL module functionality test'''

import dns.exception
import dns.message
import dns.query
import os
import time

from dnstest.libknot import libknot
from dnstest.test import Test
from dnstest.module import ModRRL
from dnstest.utils import *

ctl = libknot.control.KnotCtl()

t = Test(stress=False)

ModRRL.check()

knot = t.server("knot")
zones = t.zone_rnd(2, dnssec=False, records=1)
t.link(zones, knot)

def send_queries(server, name, run_time=1.0, query_time=0.05):
    """
    Send UDP queries to the server for certain time and get replies statistics.
    """
    replied, slipped, dropped = 0, 0, 0
    start = time.time()
    while time.time() < start + run_time:
        try:
            query = dns.message.make_query(name, "SOA", want_dnssec=False)
            response = dns.query.udp(query, server.addr, port=server.port, timeout=query_time)
        except dns.exception.Timeout:
            response = None

        if response is None:
            dropped += 1
        elif response.flags & dns.flags.TC:
            slipped += 1
        else:
            replied += 1

    return dict(replied=replied, slipped=slipped, dropped=dropped)

def check_result(name, res, rate=0, slip=None):
    """
    Check response result.

    We cannot send queries in parallel. And we have to give the server some time
    to respond, especially under valgrind. Therefore we have to be tolerant when
    counting responses when packets are being dropped.
    """
    detail_log("RRL %s" % name)
    detail_log(", ".join(["%s %d" % (s, res[s]) for s in ["replied", "slipped", "dropped"]]))

    ok = False

    if rate == 0:
        ok = res["replied"] >= 100 and res["slipped"] == 0 and res["dropped"] == 0
    elif slip == 0:
        ok = res["replied"] > 0 and res["replied"] < 100 and \
             res["slipped"] == 0 and res["dropped"] >= 5
    elif slip == 1:
        ok = res["replied"] > 0 and res["replied"] < 100 and \
             res["slipped"] >= 100 and res["dropped"] == 0
    else:
        ok = res["replied"] > 0 and res["replied"] < 100 and \
             res["slipped"] >= 5 and res["dropped"] >= 5

    if ok:
        detail_log("success")
    else:
        detail_log("error")
        set_err("RRL ERROR")

def cmp_stats(server, res, zone_name=None):
    try:
        ctl = libknot.control.KnotCtl()
        ctl.connect(os.path.join(server.dir, "knot.sock"))

        if zone_name:
            ctl.send_block(cmd="zone-stats", section="mod-rrl", zone=zone_name, flags="F")
        else:
            ctl.send_block(cmd="stats", section="mod-rrl", flags="F")

        stats = ctl.receive_stats()
        detail_log(stats)

        if zone_name:
            ok = int(stats["zone"][zone_name.lower()]["mod-rrl"]["dropped"]) == res["dropped"] and \
                 int(stats["zone"][zone_name.lower()]["mod-rrl"]["slipped"]) == res["slipped"]
        else:
            ok = int(stats["mod-rrl"]["dropped"]) == res["dropped"] and \
                 int(stats["mod-rrl"]["slipped"]) == res["slipped"]

        if ok:
            detail_log("stats success")
        else:
            detail_log("stats error")
            set_err("RRL STATS ERROR")

    finally:
        ctl.send(libknot.control.KnotCtlType.END)
        ctl.close()

def reconfigure(server, zone, rate_limit, slip, whitelist=None):
    """
    Reconfigure server module.
    """
    server.clear_modules(None)
    server.clear_modules(zone)
    server.add_module(zone, ModRRL(rate_limit=rate_limit, slip=slip, whitelist=whitelist))
    server.gen_confile()
    server.reload()

t.start()

knot.zones_wait(zones)

### RRL global module

# Disabled
res = send_queries(knot, zones[0].name)
check_result("disabled", res)

# All drop
reconfigure(knot, None, 5, 0)
res = send_queries(knot, zones[0].name)
check_result("global, zone 1, all drop", res, 5, 0)
cmp_stats(knot, res)
time.sleep(2)
res = send_queries(knot, zones[1].name)
check_result("global, zone 2, all drop", res, 5, 0)

# All slip
reconfigure(knot, None, 5, 1)
res = send_queries(knot, zones[0].name)
check_result("global, zone 1, all slip", res, 5, 1)
cmp_stats(knot, res)
time.sleep(2)
res = send_queries(knot, zones[1].name)
check_result("global, zone 2, all slip", res, 5, 1)

# 50% slip
reconfigure(knot, None, 5, 2)
res = send_queries(knot, zones[0].name)
check_result("global, zone 1, 50% slip", res, 5, 2)
cmp_stats(knot, res)
time.sleep(2)
res = send_queries(knot, zones[1].name)
check_result("global, zone 2, 50% slip", res, 5, 2)

# Whitelist
reconfigure(knot, None, 5, 0, whitelist=knot.addr)
res = send_queries(knot, zones[0].name)
cmp_stats(knot, res)
check_result("global, zone 1, whitelist", res, 0)
time.sleep(2)
res = send_queries(knot, zones[1].name)
check_result("global, zone 2, whitelist", res, 0)

### RRL zone module

# All drop
reconfigure(knot, zones[0], 5, 0)
res = send_queries(knot, zones[0].name)
check_result("zone 1, all drop", res, 5, 0)
cmp_stats(knot, res, zones[0].name)
time.sleep(2)
res = send_queries(knot, zones[1].name)
check_result("zone 2, disabled", res)

# All slip
reconfigure(knot, zones[0], 5, 1)
res = send_queries(knot, zones[0].name)
check_result("zone 1, all slip", res, 5, 1)
cmp_stats(knot, res, zones[0].name)
time.sleep(2)
res = send_queries(knot, zones[1].name)
check_result("zone 2, disabled", res)

# 50% slip
reconfigure(knot, zones[0], 5, 2)
res = send_queries(knot, zones[0].name)
check_result("zone 1, 50% slip", res, 5, 2)
cmp_stats(knot, res, zones[0].name)
time.sleep(2)
res = send_queries(knot, zones[1].name)
check_result("zone 2, disabled", res)

# Whitelist
reconfigure(knot, zones[0], 5, 0, whitelist=knot.addr)
res = send_queries(knot, zones[0].name)
check_result("zone 1, whitelist", res, 0)
cmp_stats(knot, res, zones[0].name)
time.sleep(2)
res = send_queries(knot, zones[1].name)
check_result("zone 2, disabled", res)

t.end()
