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

def reconfigure(server, zone, badcookie_slip, secret_lifetime = None, secret = None):
    """
    Reconfigure server module.
    """
    server.clear_modules(None)
    server.add_module(None, ModCookies(secret_lifetime=secret_lifetime,
                      badcookie_slip=badcookie_slip, secret=secret))
    server.gen_confile()
    server.reload()
    server.zone_wait(zone)

def check_rcode(server, query, rcode, msg, tcp=False):
    try:
        if tcp:
            response = dns.query.tcp(query, server.addr, port=server.port, timeout=1)
        else:
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

reconfigure(knot, zone, 1, secret_lifetime=5)

# Try a query without EDNS
query = dns.message.make_query("dns1.example.com", "A", use_edns=False)
check_rcode(knot, query, rcodeNoerror, "NO EDNS")

# Try a query without a cookie option
query = dns.message.make_query("dns1.example.com", "A", use_edns=True)
check_rcode(knot, query, rcodeNoerror, "NO COOKIE OPT")

# Try a query without a server cookie over TCP
cookieOpt = dns.edns.option_from_wire(cookieOpcode, clientCookie, 0, clientCookieLen)
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt])
response = check_rcode(knot, query, rcodeNoerror, "ONLY CLIENT COOKIE [TCP]", tcp=True)

# Try a query with the received cookie over TCP
cookieOpt = response.options[0]
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt])
check_rcode(knot, query, rcodeNoerror, "CORRECT COOKIE [TCP]", tcp=True)

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

reconfigure(knot, zone, 4, secret_lifetime=1000000)

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

reconfigure(knot, zone, 1, secret=[b'\xde\xad\xbe\xef\xde\xad\xbe\xef\xde\xad\xbe\xef\xde\xad\xbe\xef'])

# Try a query without a cookie option
query = dns.message.make_query("dns1.example.com", "A", use_edns=True)
check_rcode(knot, query, rcodeNoerror, "NO COOKIE OPT 2")

# Try a query without a server cookie over TCP
cookieOpt = dns.edns.option_from_wire(cookieOpcode, clientCookie, 0, clientCookieLen)
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt])
response = check_rcode(knot, query, rcodeNoerror, "ONLY CLIENT COOKIE [TCP] 2", tcp=True)

# Try a query with the received cookie over TCP
cookieOpt = response.options[0]
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt])
check_rcode(knot, query, rcodeNoerror, "CORRECT COOKIE 3", tcp=True)

# Try a query without a server cookie
cookieOpt = dns.edns.option_from_wire(cookieOpcode, clientCookie, 0, clientCookieLen)
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt])
response = check_rcode(knot, query, rcodeBadcookie, "ONLY CLIENT COOKIE 3")

# Try a query with the received cookie
cookieOpt = response.options[0]
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt])
check_rcode(knot, query, rcodeNoerror, "CORRECT COOKIE 4")

reconfigure(knot, zone, 1, secret=[b'\x8b\xad\xf0\x0d\x8b\xad\xf0\x0d\x8b\xad\xf0\x0d\x8b\xad\xf0\x0d', b'\xde\xad\xbe\xef\xde\xad\xbe\xef\xde\xad\xbe\xef\xde\xad\xbe\xef'])

# Try the same cookie after the secret rollover
response = check_rcode(knot, query, rcodeNoerror, "ROLLOVER 2")

# Try a query with the new received cookie
cookieOpt = response.options[0]
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt])
response = check_rcode(knot, query, rcodeNoerror, "CORRECT COOKIE 5")

# Try a query without a server cookie over TCP
cookieOpt = dns.edns.option_from_wire(cookieOpcode, clientCookie, 0, clientCookieLen)
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt])
response = check_rcode(knot, query, rcodeNoerror, "ONLY CLIENT COOKIE [TCP] 3", tcp=True)

# Try a query with the received cookie over TCP
cookieOpt = response.options[0]
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt])
check_rcode(knot, query, rcodeNoerror, "CORRECT COOKIE [TCP] 2", tcp=True)

# Try a query without a server cookie
cookieOpt = dns.edns.option_from_wire(cookieOpcode, clientCookie, 0, clientCookieLen)
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt])
response = check_rcode(knot, query, rcodeBadcookie, "ONLY CLIENT COOKIE 4")

# Try a query with the received cookie
cookieOpt = response.options[0]
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt])
check_rcode(knot, query, rcodeNoerror, "CORRECT COOKIE 6")

t.end()
