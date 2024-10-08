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

def send_queries(server, name, run_time=None, query_time=None):
    """
    Send UDP queries to the server for certain time and get replies statistics.
    """
    if run_time is None:
        run_time = 2.0 if not server.valgrind else 3.0
    if query_time is None:
        query_time = 0.15 if not server.valgrind else 0.25

    replied, slipped, dropped = 0, 0, 0
    start = time.time()
    while time.time() < start + run_time:
        try:
            query = dns.message.make_query(name, "SOA", want_dnssec=False)
            response = dns.query.udp(query, server.addr, port=server.port, \
                                     source=server.addr, timeout=query_time)
        except dns.exception.Timeout:
            response = None

        if response is None:
            dropped += 1
        elif response.flags & dns.flags.TC:
            slipped += 1
            if not response.flags & dns.flags.AA:
                detail_log("missing AA flag")
                set_err("RRL ERROR")
        else:
            replied += 1

        if response is not None and response.rcode() != dns.rcode.NOERROR:
            detail_log("unexpected RCODE %s, wanted NOERROR" % response.rcode())
            set_err("RRL ERROR")

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
        ok = res["replied"] >= 100 and res["slipped"] == 0 and res["dropped"] <= 3
    elif slip == 0:
        ok = res["replied"] > 0 and res["replied"] < 100 and \
             res["slipped"] == 0 and res["dropped"] >= 5
    elif slip == 1:
        ok = res["replied"] > 0 and res["replied"] < 100 and \
             res["slipped"] >= 100 and res["dropped"] <= 3
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
            ok = int(abs(stats["zone"][zone_name.lower()]["mod-rrl"]["dropped"] - res["dropped"]) <= 1) and \
                 int(abs(stats["zone"][zone_name.lower()]["mod-rrl"]["slipped"] - res["slipped"]) <= 1)
        else:
            ok = int(abs(stats["mod-rrl"]["dropped"] - res["dropped"]) <= 1) and \
                 int(abs(stats["mod-rrl"]["slipped"] - res["slipped"]) <= 1)

        if ok:
            detail_log("stats success")
        else:
            detail_log("stats error")
            set_err("RRL STATS ERROR")

    finally:
        ctl.send(libknot.control.KnotCtlType.END)
        ctl.close()

def reconfigure(server, zone, limit, slip, whitelist=None):
    """
    Reconfigure server module.
    """
    server.clear_modules(None)
    server.clear_modules(zone)
    server.add_module(zone, ModRRL(rate_limit=limit, instant_limit=limit, slip=slip,
                      whitelist=whitelist, log_period=1500))
    server.gen_confile()
    server.reload()

t.start()

knot.zones_wait(zones)

### RRL global module

# Disabled
res = send_queries(knot, zones[0].name)
check_result("disabled", res)
detail_log(SEP)

# All drop
reconfigure(knot, None, 5, 0)
res = send_queries(knot, zones[0].name)
check_result("global, zone 1, all drop", res, 5, 0)
cmp_stats(knot, res)
time.sleep(2)
res = send_queries(knot, zones[1].name)
check_result("global, zone 2, all drop", res, 5, 0)
detail_log(SEP)

# All slip
reconfigure(knot, None, 5, 1)
res = send_queries(knot, zones[0].name)
check_result("global, zone 1, all slip", res, 5, 1)
cmp_stats(knot, res)
time.sleep(2)
res = send_queries(knot, zones[1].name)
check_result("global, zone 2, all slip", res, 5, 1)
detail_log(SEP)

# 50% slip
reconfigure(knot, None, 5, 2)
res = send_queries(knot, zones[0].name, run_time=5.0)
check_result("global, zone 1, 50% slip", res, 5, 2)
cmp_stats(knot, res)
time.sleep(2)
res = send_queries(knot, zones[1].name, run_time=5.0)
check_result("global, zone 2, 50% slip", res, 5, 2)
detail_log(SEP)

# Whitelist
reconfigure(knot, None, 5, 0, whitelist=knot.addr)
res = send_queries(knot, zones[0].name)
check_result("global, zone 1, whitelist", res, 0)
cmp_stats(knot, res)
time.sleep(2)
res = send_queries(knot, zones[1].name)
check_result("global, zone 2, whitelist", res, 0)
detail_log(SEP)

### RRL zone module

# All drop
reconfigure(knot, zones[0], 5, 0)
res = send_queries(knot, zones[0].name)
check_result("zone 1, all drop", res, 5, 0)
cmp_stats(knot, res, zones[0].name)
time.sleep(2)
res = send_queries(knot, zones[1].name)
check_result("zone 2, disabled", res)
detail_log(SEP)

# All slip
reconfigure(knot, zones[0], 5, 1)
res = send_queries(knot, zones[0].name)
check_result("zone 1, all slip", res, 5, 1)
cmp_stats(knot, res, zones[0].name)
time.sleep(2)
res = send_queries(knot, zones[1].name)
check_result("zone 2, disabled", res)
detail_log(SEP)

# 50% slip
reconfigure(knot, zones[0], 5, 2)
res = send_queries(knot, zones[0].name, run_time=5.0)
check_result("zone 1, 50% slip", res, 5, 2)
cmp_stats(knot, res, zones[0].name)
time.sleep(2)
res = send_queries(knot, zones[1].name, run_time=5.0)
check_result("zone 2, disabled", res)
detail_log(SEP)

# Whitelist
reconfigure(knot, zones[0], 5, 0, whitelist=knot.addr)
res = send_queries(knot, zones[0].name)
check_result("zone 1, whitelist", res, 0)
cmp_stats(knot, res, zones[0].name)
time.sleep(2)
res = send_queries(knot, zones[1].name)
check_result("zone 2, disabled", res)
detail_log(SEP)

t.end()
