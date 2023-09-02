#!/usr/bin/env python3

'''Test for YAML statistics'''

import os
import yaml
import dns.message
import dns.query

from dnstest.libknot import libknot
from dnstest.module import ModRRL
from dnstest.module import ModStats
from dnstest.test import Test
from dnstest.utils import *

def send_queries(server, name, count):
    for i in range(count):
        try:
            query = dns.message.make_query(name, "SOA", want_dnssec=False)
            response = dns.query.udp(query, server.addr, port=server.port, timeout=0.2)
        except dns.exception.Timeout:
            pass

def read_yaml(path):
    counter = 0
    while not os.path.exists(STATS_YAML):
        if counter > 9: break
        counter += 1
        t.sleep(0.5)

    with open(STATS_YAML, "r") as stream:
        try:
            return yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            set_err("FAILED TO READ YAML STATS")

def check_common(yaml):
    isset(y['identity'] == 'yaml_test', "identity value")

    server = y['server']
    isset(server['zone-count'] == 1, "non-empty server value")

ModRRL.check()
ModStats.check()

ctl = libknot.control.KnotCtl()

t = Test(stress=False, address=4)

ZONE = "example.com."
knot = t.server("knot", ident="yaml_test")
zone = t.zone(ZONE)
t.link(zone, knot)

knot.add_module(zone[0], ModRRL(rate_limit=1, slip=0))
knot.add_module(None,    ModStats())
knot.add_module(zone[0], ModStats())

t.start()

STATS_YAML = os.path.join(knot.dir, "stats.yaml")

ctl.connect(os.path.join(knot.dir, "knot.sock"))
ctl.send_block(cmd="conf-begin")
resp = ctl.receive_block()
ctl.send_block(cmd="conf-set", section="statistics", item="file", data=STATS_YAML)
resp = ctl.receive_block()
ctl.send_block(cmd="conf-set", section="statistics", item="timer", data="1")
resp = ctl.receive_block()
ctl.send_block(cmd="conf-commit")
resp = ctl.receive_block()
ctl.send(libknot.control.KnotCtlType.END)
ctl.close()

y = read_yaml(STATS_YAML)
check_common(y)

isset('mod-stats' not in y, "missing mod-stats")

os.remove(STATS_YAML)
send_queries(knot, ZONE, 10)

y = read_yaml(STATS_YAML)
check_common(y)

stats = y['mod-stats']
isset(stats['request-protocol']['udp4'] > 0, "non-empty module value")
isset('udp6' not in stats['request-protocol'], "missing module value")

stats_zone = y['zone'][ZONE]['mod-stats']
isset(stats_zone['request-protocol']['udp4'] > 0, "non-empty module value")
isset('udp6' not in stats_zone['request-protocol'], "missing module value")

rrl = y['zone'][ZONE]['mod-rrl']
isset(rrl['dropped'] > 0, "non-empty module value")
isset('slipped' not in rrl, "missing module value")

t.end()
