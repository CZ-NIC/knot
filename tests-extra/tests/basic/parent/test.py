#!/usr/bin/env python3

'''Proper answering when parent+child configured.'''

from dnstest.test import Test
from dnstest.utils import *
import random
import shutil


t = Test()

knot = t.server("knot")
parent = t.zone("parent.", storage=".")
child = t.zone("child.parent.", storage=".")

t.link(parent + child, knot)

t.start()
knot.zones_wait(parent + child)

resp = knot.dig("cname." + parent[0].name, "A")
resp.check_count(1, "CNAME")
resp.check(rcode="NOERROR", nordata="192.0.2.100")

t.end()
