#!/usr/bin/env python3

'''cookies module functionality test'''

import dns.exception
import dns.message
import dns.query
import dns.edns
import os
import time

from dnstest.test import Test
from dnstest.module import ModCookies
from dnstest.utils import *

clientCookie = bytearray(b'\xde\xad\xbe\xef\xfe\xeb\xda\xed')
clientCookieLen = 8
cookieOpcode = 10
rcodeNoerror = 0
rcodeBadcookie = 23

def reconfigure(server, zone, secret_lifetime, badcookie_slip):
    """
    Reconfigure server module.
    """
    server.clear_modules(None)
    server.add_module(None, ModCookies(secret_lifetime=secret_lifetime,
                      badcookie_slip=badcookie_slip))
    server.gen_confile()
    server.reload()
    server.zone_wait(zone)

def check_rcode(server, query, rcode, msg):
    try:
        response = dns.query.udp(query, server.addr, port=server.port, timeout=1)
    except dns.exception.Timeout:
        response = None
    if response is None:
        return None
    compare(response.rcode(), rcode, msg)
    return response

t = Test(stress=False)

ModCookies.check()

knot = t.server("knot")
zone = t.zone("example.com")

t.link(zone, knot)

t.start()

reconfigure(knot, zone, 5, 1)

# Try a query without EDNS
query = dns.message.make_query("dns1.example.com", "A", use_edns=False)
check_rcode(knot, query, rcodeNoerror, "NO EDNS")

# Try a query without a cookie option
query = dns.message.make_query("dns1.example.com", "A", use_edns=True)
check_rcode(knot, query, rcodeNoerror, "NO COOKIE OPT")

# Try a query without a server cookie
cookieOpt = dns.edns.option_from_wire(cookieOpcode, clientCookie, 0, clientCookieLen)
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt])
response = check_rcode(knot, query, rcodeBadcookie, "ONLY CLIENT COOKIE")

# Try a query with the received cookie
cookieOpt = response.options[0]
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt])
check_rcode(knot, query, rcodeNoerror, "CORRECT COOKIE")

# Try the same cookie after the secret rollover
time.sleep(6)
response = check_rcode(knot, query, rcodeBadcookie, "ROLLOVER")

# Try a query with the new received cookie
cookieOpt = response.options[0]
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt])
response = check_rcode(knot, query, rcodeNoerror, "CORRECT COOKIE 2")

reconfigure(knot, zone, 1000000, 4)

cookieOpt = dns.edns.option_from_wire(cookieOpcode, clientCookie, 0, clientCookieLen)
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt]);
response = check_rcode(knot, query, rcodeBadcookie, "ONLY CLIENT COOKIE 2")

# Next 3 attempts to get the server cookie should timeout
for i in range(3):
    query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt]);
    response = check_rcode(knot, query, rcodeNoerror, "TIMEOUT "+str(i))
    compare(response, None, "BADCOOKIE TIMEOUT " + str(i))

# The 4th attempt should succeed
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt]);
check_rcode(knot, query, rcodeBadcookie, "BADCOOKIE")

t.end()
