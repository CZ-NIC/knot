#!/usr/bin/env python3

''' Check 'dnstap' query module functionality. '''

import os
import re
import dns
from dnstest.test import Test
from dnstest.module import ModDnstap
from dnstest.utils import *

# --- Simple DNSTAP file parser ---

def read_byte(f, left):
    if left[0] < 1:
        return 0
    left[0] -= 1
    return f.read(1)[0]

def read_be32(f, left):
    if left[0] < 4:
        return 0
    left[0] -= 4
    be = f.read(4)
    return (be[0] << 24) + (be[1] << 16) + (be[2] << 8) + be[3]

def pb_varint(f, left):
    x = 0
    shift = 0
    while True:
        b = read_byte(f, left)
        x += ((b & 0x7f) << shift)
        if (b & 0x80) == 0:
            return x
        shift += 7

def pb_skip2field(f, left, field):
    while left[0] > 0:
        b = read_byte(f, left)
        if (b >> 3) == field:
            return ((b & 0x2) != 0)
        if (b & 0x1) != 0:
            valen = 4 if (b & 0x7) == 5 else 8
            left[0] -= valen
            _ = f.read(valen)
        else:
            val = pb_varint(f, left)
            if (b & 0x2) != 0: # val is length
                left[0] -= val
                _ = f.read(val)

def sd_file(f, msg, field, subfield):
    left = [ 2**62 ]

    # skip intro frame
    zero = read_be32(f, left)
    if zero != 0:
        return None
    intro = read_be32(f, left)
    _ = f.read(intro)

    # skip to n-th msg
    for imsg in range(msg):
        skip = read_be32(f, left)
        _ = f.read(skip)

    left[0] = read_be32(f, left)
    # now continue with protobuf format

    haslen = pb_skip2field(f, left, field)
    if subfield is not None:
        if not haslen:
            return None
        left_prev = left[0]
        left[0] = pb_varint(f, left)
        if left_prev < left[0]:
            return None
        haslen = pb_skip2field(f, left, subfield)

    val = pb_varint(f, left)
    if haslen:
        return f.read(val) if left[0] >= val else None
    else:
        return val

def simple_dnstap(file, msg, field, subfield=None):
    with open(file, "rb") as f:
        return sd_file(f, msg, field, subfield)

# --- Simple DNSTAP file parser end ---

def sink_contains(sink, qname):
    try:
        for msg in range(1000): # in practice, while(!exception)
            query = simple_dnstap(sink, msg, 14, 10)
            if query is None or query == 0:
                continue
            qr = dns.message.from_wire(query)
            if str(qr.question[0].name) == str(qname):
                return True
    except Exception as e:
        return False
    return False

def sink_contains_proto(sink, proto):
    try:
        for msg in range(1000): # in practice, while(!exception)
            prot = simple_dnstap(sink, msg, 14, 3)
            if prot == proto:
                return True
    except Exception as e:
        return False
    return False

t = Test(quic=True, stress=False)

ModDnstap.check()

# Initialize server configuration
knot = t.server("knot")
slave = t.server("knot")
zone = t.zone("flags.")
t.link(zone, knot, slave)

# Configure 'dnstap' module for all queries (default).
dflt_sink = t.out_dir + "/all.tap"
knot.add_module(None, ModDnstap(dflt_sink))
# Configure 'dnstap' module for flags zone only.
flags_sink = t.out_dir + "/flags.tap"
knot.add_module(zone, ModDnstap(flags_sink))

t.start()

slave.zone_wait(zone)

dflt_qname = "dnstap_default_test" + ".example."
resp = knot.dig(dflt_qname, "NS")
flags_qname = "dnstap_flags_test" + ".flags."
resp = knot.dig(flags_qname, "NS")

knot.stop()

# Check if dnstap sinks exist.
isset(os.path.isfile(dflt_sink), "default sink")
isset(os.path.isfile(flags_sink), "zone sink")

# Check sink contents.
isset(sink_contains(dflt_sink, flags_qname), "qname '%s' in '%s'" % (flags_qname, dflt_sink))
isset(sink_contains(dflt_sink, dflt_qname), "qname '%s' in '%s'" % (dflt_qname, dflt_sink))
isset(sink_contains(flags_sink, flags_qname), "qname '%s' in '%s'" % (flags_qname, flags_sink))
isset(not sink_contains(flags_sink, dflt_qname), "qname '%s' in '%s'" % (dflt_qname, flags_sink))

isset(sink_contains_proto(dflt_sink, 7), "QUIC in '%s'" % dflt_sink)
isset(sink_contains_proto(flags_sink, 7), "QUIC in '%s'" % flags_sink)

t.end()
