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

secret1 = bytearray(b'\xde\xad\xbe\xef\xde\xad\xbe\xef\xde\xad\xbe\xef\xde\xad\xbe\xef')
secret2 = bytearray(b'\x8b\xad\xf0\x0d\x8b\xad\xf0\x0d\x8b\xad\xf0\x0d\x8b\xad\xf0\x0d')
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
check_rcode(knot, query, rcodeNoerror, "CORRECT COOKIE", tcp=True)

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
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt])
response = check_rcode(knot, query, rcodeBadcookie, "ONLY CLIENT COOKIE 2")

# Next 3 attempts to get the server cookie should timeout
for i in range(3):
    query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt])
    response = check_rcode(knot, query, rcodeNoerror, "TIMEOUT "+str(i))
    compare(response, None, "BADCOOKIE TIMEOUT " + str(i))

# The 4th attempt should succeed
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt])
check_rcode(knot, query, rcodeBadcookie, "BADCOOKIE")

## Fixed secret(s)

reconfigure(knot, zone, 1, secret=[secret1])

# Receive a server cookie for secret1
cookieOpt = dns.edns.option_from_wire(cookieOpcode, clientCookie, 0, clientCookieLen)
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt])
response = check_rcode(knot, query, rcodeBadcookie, "ONLY CLIENT COOKIE - SECRET1")

# Try a query with the received cookie
cookieOpt1 = response.options[0]
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt1])
check_rcode(knot, query, rcodeNoerror, "CORRECT COOKIE - SECRET1")

reconfigure(knot, zone, 1, secret=[secret2])

# Re-try a query with the received cookie against secret2
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt1])
response = check_rcode(knot, query, rcodeBadcookie, "BADCOOKIE - SECRET2")
cookieOpt2 = response.options[0]

# Re-try a query with the received cookie against secret1 again
reconfigure(knot, zone, 1, secret=[secret1])
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt1])
check_rcode(knot, query, rcodeNoerror, "CORRECT COOKIE - SECRET1")

reconfigure(knot, zone, 1, secret=[secret2, secret1])

# Re-try cookie with secret1
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt1])
check_rcode(knot, query, rcodeNoerror, "CORRECT COOKIE - SECRET1,2")

# Re-try cookie with secret2
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt2])
check_rcode(knot, query, rcodeNoerror, "CORRECT COOKIE - SECRET2,1")

# Get new server cookie when two secret are configured
cookieOpt = dns.edns.option_from_wire(cookieOpcode, clientCookie, 0, clientCookieLen)
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt])
response = check_rcode(knot, query, rcodeBadcookie, "ONLY CLIENT COOKIE - SECRET2,1")
cookieOpt21 = response.options[0]

reconfigure(knot, zone, 1, secret=[secret2])

# Re-try cookie with first secret2
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt21])
check_rcode(knot, query, rcodeNoerror, "CORRECT COOKIE - SECRET2,1")

t.end()
