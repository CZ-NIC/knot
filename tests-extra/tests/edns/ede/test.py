#!/usr/bin/env python3

'''Test extended error in EDNS (EDE).'''

from dnstest.test import Test
from dnstest.utils import *
import os
import struct
import dns.edns

KNOT_EDNS_OPTION_EDE = 15

# this will work with future dnspython...
#class EdeOption(dns.edns.Option):
#   def __init__(self, rcode):
#      super().__init__(KNOT_EDNS_OPTION_EDE)
#      self.rcode = rcode
#   def to_text():
#      return "EDE d" % rcode
#   def to_wire(self, file=None):
#      value = struct.pack('!H', self.rcode)
#      if file:
#         file.write(value)
#      else:
#         return value
#   @classmethod
#   def from_wire_parser(cls, otype, parser):
#        rcode = parser.get_uint16()
#        print("parsed " + rcode)
#        return cls(rcode)
#dns.edns.register_type(EdeOption, KNOT_EDNS_OPTION_EDE)

def get_ede_rcode(option):
   assert isinstance(option, dns.edns.GenericOption)
   assert len(option.data) == 2
   return struct.unpack('!H', option.data)[0]

def get_ede(server, expect_ede, msg, qname, qtype="SOA"):
   resp = server.dig(qname, qtype, edns=0)
   ede = None
   for o in resp.resp.options:
      if o.otype == KNOT_EDNS_OPTION_EDE:
         if ede is not None:
            set_err(msg + ": multiple EDE")
         ede = o

   if ede is None and expect_ede is not None:
      set_err(msg + ": EDE expected")
      detail_log(resp.resp.to_text())
   elif ede is not None and expect_ede is None:
      set_err(msg + ": EDE unexpected")
   elif ede is not None:
      ede_rcode = get_ede_rcode(ede)
      if ede_rcode != expect_ede:
         set_err(msg + ": wrong EDE %d != %d" % (ede_rcode, expect_ede))

KNOT_EDNS_EDE_OTHER            = 0
KNOT_EDNS_EDE_DNSKEY_ALG       = 1
KNOT_EDNS_EDE_DS_DIGEST        = 2
KNOT_EDNS_EDE_STALE            = 3
KNOT_EDNS_EDE_FORGED           = 4
KNOT_EDNS_EDE_INDETERMINATE    = 5
KNOT_EDNS_EDE_BOGUS            = 6
KNOT_EDNS_EDE_SIG_EXPIRED      = 7
KNOT_EDNS_EDE_SIG_NOTYET       = 8
KNOT_EDNS_EDE_DNSKEY_MISS      = 9
KNOT_EDNS_EDE_RRSIG_MISS       = 10
KNOT_EDNS_EDE_DNSKEY_BIT       = 11
KNOT_EDNS_EDE_NSEC_MISS        = 12
KNOT_EDNS_EDE_CACHED_ERR       = 13
KNOT_EDNS_EDE_NOT_READY        = 14
KNOT_EDNS_EDE_BLOCKED          = 15
KNOT_EDNS_EDE_CENSORED         = 16
KNOT_EDNS_EDE_FILTERED         = 17
KNOT_EDNS_EDE_PROHIBITED       = 18
KNOT_EDNS_EDE_STALE_NXD        = 19
KNOT_EDNS_EDE_NOTAUTH          = 20
KNOT_EDNS_EDE_NOTSUP           = 21
KNOT_EDNS_EDE_NREACH_AUTH      = 22
KNOT_EDNS_EDE_NETWORK          = 23
KNOT_EDNS_EDE_INV_DATA         = 24

t = Test()

zones = t.zone_rnd(2)

master = t.server("knot")

t.link(zones, master)

os.remove(master.zones[zones[1].name].zfile.path)

t.start()
master.zone_wait(zones[0])

get_ede(master, KNOT_EDNS_EDE_INV_DATA,   "Not loaded",  zones[1].name)
get_ede(master, KNOT_EDNS_EDE_NOTAUTH,    "Out of zone", "out.of.zone.")

t.stop()
