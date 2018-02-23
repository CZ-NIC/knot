#!/usr/bin/env python3

''' Check 'stats' query module functionality. '''

import os
import random

from dnstest.libknot import libknot
from dnstest.module import ModStats
from dnstest.test import Test
from dnstest.utils import *

def check_item(server, section, item, value, idx=None, zone=None):
    try:
        ctl = libknot.control.KnotCtl()
        ctl.connect(os.path.join(server.dir, "knot.sock"))

        if zone:
            ctl.send_block(cmd="zone-stats", section=section, item=item, zone=zone.name)
        else:
            ctl.send_block(cmd="stats", section=section, item=item)

        stats = ctl.receive_stats()
    finally:
        ctl.send(libknot.control.KnotCtlType.END)
        ctl.close()

    if not stats and value == -1:
        return

    if zone:
        stats = stats.get("zone").get(zone.name.lower())

    if idx:
        if value == -1:
            isset(idx not in stats.get(section).get(item), idx)
            return
        else:
            data = int(stats.get(section).get(item).get(idx))
    else:
        data = int(stats.get(section).get(item))

    compare(data, value, "%s.%s" % (section, item))

ModStats.check()

proto = random.choice([4, 6])

t = Test(stress=False, tsig=False, address=proto)

knot = t.server("knot")
zones = t.zone_rnd(2)

t.link(zones, knot)

knot.add_module(None,     ModStats())
knot.add_module(zones[0], ModStats())
knot.add_module(zones[1], ModStats())

t.start()
t.sleep(4)

check_item(knot, "server", "zone-count", 2)

resp = knot.dig(zones[0].name, "SOA", tries=1, udp=True)
query_size1 = resp.query_size()
reply_size1 = resp.response_size()

resp = knot.dig(zones[0].name, "NS", tries=1, udp=False)
query_size2 = resp.query_size()
reply_size2 = resp.response_size()

resp = knot.dig(zones[1].name, "TYPE11", tries=1, udp=True)
query_size3 = resp.query_size()
reply_size3 = resp.response_size()

# Successful transfer.
resp = knot.dig(zones[0].name, "AXFR", tries=1)
resp.check_xfr(rcode="NOERROR")
xfr_query_size = resp.query_size()
# Cannot get xfr_reply_size :-/

# Successful update.
up = knot.update(zones[1])
up.add(zones[1].name, "3600", "AAAA", "::1")
up.send("NOERROR")
ddns_query_size = up.query_size()
# Due to DDNS bulk processing, failed RCODE and response-bytes are not incremented!

# Check request protocol metrics.
check_item(knot, "mod-stats", "request-protocol", 2, "udp%s" % proto)
check_item(knot, "mod-stats", "request-protocol", 1, "udp%s" % proto, zone=zones[0])
check_item(knot, "mod-stats", "request-protocol", 1, "udp%s" % proto, zone=zones[1])

check_item(knot, "mod-stats", "request-protocol", 3, "tcp%s" % proto)
check_item(knot, "mod-stats", "request-protocol", 2, "tcp%s" % proto, zone=zones[0])

# Check request/response bytes metrics.
check_item(knot, "mod-stats", "request-bytes",  query_size1 + query_size2 + query_size3,
                                                "query")
check_item(knot, "mod-stats", "request-bytes",  ddns_query_size, "update")
check_item(knot, "mod-stats", "request-bytes",  xfr_query_size, "other")

check_item(knot, "mod-stats", "response-bytes", reply_size1 + reply_size2 + reply_size3,
                                                "reply")

check_item(knot, "mod-stats", "request-bytes",  query_size1 + query_size2, "query",
                                                zone=zones[0])
check_item(knot, "mod-stats", "response-bytes", reply_size1 + reply_size2, "reply",
                                                zone=zones[0])

check_item(knot, "mod-stats", "request-bytes",  query_size3, "query", zone=zones[1])
check_item(knot, "mod-stats", "response-bytes", reply_size3, "reply", zone=zones[1])

# Check query size metrics (just for global module).
indices = dict()
for size in [query_size1, query_size2, query_size3]:
    idx = "%i-%i" % (int(size / 16) * 16, int(size / 16) * 16 + 15)
    if idx not in indices:
        indices[idx] = 1
    else:
        indices[idx] += 1;
for size in indices:
    check_item(knot, "mod-stats", "query-size", indices[size], idx=size)

# Check reply size metrics (just for global module).
indices = dict()
for size in [reply_size1, reply_size2, reply_size3]:
    idx = "%i-%i" % (int(size / 16) * 16, int(size / 16) * 16 + 15)
    if idx not in indices:
        indices[idx] = 1
    else:
        indices[idx] += 1;
for size in indices:
    check_item(knot, "mod-stats", "reply-size", indices[size], idx=size)

# Check query type metrics.
check_item(knot, "mod-stats", "query-type",  1, idx="SOA")
check_item(knot, "mod-stats", "query-type",  1, idx="NS")
check_item(knot, "mod-stats", "query-type",  1, idx="TYPE11")

check_item(knot, "mod-stats", "query-type",  1, idx="SOA",    zone=zones[0])
check_item(knot, "mod-stats", "query-type",  1, idx="NS",     zone=zones[0])
check_item(knot, "mod-stats", "query-type", -1, idx="TYPE11", zone=zones[0])

check_item(knot, "mod-stats", "query-type", -1, idx="SOA",    zone=zones[1])
check_item(knot, "mod-stats", "query-type", -1, idx="NS",     zone=zones[1])
check_item(knot, "mod-stats", "query-type",  1, idx="TYPE11", zone=zones[1])

# Check server operation metrics.
check_item(knot, "mod-stats", "server-operation", 3, idx="query")
check_item(knot, "mod-stats", "server-operation", 1, idx="axfr")
check_item(knot, "mod-stats", "server-operation", 1, idx="update")

# Check response code metrics.
check_item(knot, "mod-stats", "response-code", 4, idx="NOERROR")
check_item(knot, "mod-stats", "response-code", 3, idx="NOERROR", zone=zones[0])
check_item(knot, "mod-stats", "response-code", 1, idx="NOERROR", zone=zones[1])

# Check nodata metrics.
check_item(knot, "mod-stats", "reply-nodata",  1, idx="other")
check_item(knot, "mod-stats", "reply-nodata", -1, idx="other", zone=zones[0])
check_item(knot, "mod-stats", "reply-nodata",  1, idx="other", zone=zones[1])

t.end()
