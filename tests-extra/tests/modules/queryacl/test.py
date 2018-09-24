#!/usr/bin/env python3

'''Test for queryacl module'''

from dnstest.utils import *
from dnstest.test import Test
import random

t = Test()

knot = t.server("knot")
zones = t.zone_rnd(5, dnssec=False, records=50) + t.zone("records.")

t.link(zones, knot)

t.start()


t.end()
