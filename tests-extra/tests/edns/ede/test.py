#!/usr/bin/env python3

'''Test extended error in EDNS (EDE).'''

from dnstest.test import Test
from dnstest.utils import *
import os
import struct
import dns.edns

def get_ede_rcode(option):
   assert isinstance(option, dns.edns.EDEOption)
   return option.code

def get_ede(server, expect_ede, msg, qname, qtype="SOA"):
   resp = server.dig(qname, qtype, edns=0)
   ede = None
   for o in resp.resp.options:
      if o.otype == dns.edns.OptionType.EDE:
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

t = Test()

zones = t.zone_rnd(2)

master = t.server("knot")

t.link(zones, master)

os.remove(master.zones[zones[1].name].zfile.path)

t.start()
master.zone_wait(zones[0])

get_ede(master, dns.edns.EDECode.INVALID_DATA,      "Not loaded",  zones[1].name)
get_ede(master, dns.edns.EDECode.NOT_AUTHORITATIVE, "Out of zone", "out.of.zone.")

t.stop()
