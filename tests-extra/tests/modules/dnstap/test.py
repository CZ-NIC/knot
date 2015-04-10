#!/usr/bin/env python3

''' Check 'dnstap' query module functionality. '''

import os
import re
from dnstest.test import Test
from dnstest.module import ModDnstap
from dnstest.utils import *

t = Test()

ModDnstap.check()

# Initialize server configuration
knot = t.server("knot")
zone = t.zone("flags.")
t.link(zone, knot)

# Configure 'dnstap' module for all queries (default).
dflt_sink = t.out_dir + "/all.tap"
knot.add_module(None, ModDnstap(dflt_sink))
# Configure 'dnstap' module for flags zone only.
flags_sink = t.out_dir + "/flags.tap"
knot.add_module(zone, ModDnstap(flags_sink))

t.start()

dflt_qname = "dnstap_default_test"
resp = knot.dig(dflt_qname + ".example", "NS")
flags_qname = "dnstap_flags_test"
resp = knot.dig(flags_qname + ".flags", "NS")

knot.stop()

# Check if dnstap sinks exist.
isset(os.path.isfile(dflt_sink), "default sink")
isset(os.path.isfile(flags_sink), "zone sink")

def sink_contains(sink, qname):
    '''Checks the sink if contains QNAME'''

    f = open(sink, "rb")
    s = str(f.read())
    f.close()

    return s.find(qname) != -1

# Check sink contents.
isset(sink_contains(dflt_sink, flags_qname), "qname '%s' in '%s'" % (flags_qname, dflt_sink))
isset(sink_contains(dflt_sink, dflt_qname), "qname '%s' in '%s'" % (dflt_qname, dflt_sink))
isset(sink_contains(flags_sink, flags_qname), "qname '%s' in '%s'" % (flags_qname, flags_sink))
isset(not sink_contains(flags_sink, dflt_qname), "qname '%s' in '%s'" % (dflt_qname, flags_sink))

t.end()
