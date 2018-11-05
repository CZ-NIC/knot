#!/usr/bin/env python3

'''geoip module functionality test'''

from dnstest.test import Test
from dnstest.module import ModGeoip
from dnstest.utils import *
from subprocess import Popen, PIPE
import random
import re

def check_mmdb():
    '''Checks the server binary for the MMDB_open function'''

    try:
        proc = Popen(ModGeoip._check_cmd(), stdout=PIPE, stderr=PIPE,
                     universal_newlines=True)
        (out, err) = proc.communicate()
        if re.search("MMDB_open", out):
            return
        raise Skip()
    except:
        raise Skip("libmaxminddb not detected")

t = Test(address=4, stress=False)
knot = t.server("knot")

zone = t.zone("example.com.", storage=".")
t.link(zone, knot)

ModGeoip.check()
check_mmdb()

mod_geoip = ModGeoip(t.data_dir + "geo.conf", "geodb", t.data_dir + "db.mmdb", ["country/iso_code", "(id)city/geoname_id"])
knot.add_module(zone, mod_geoip);

t.start()

knot.zone_wait(zone)

# Test default answer.
resp = knot.dig("foo.example.com", "A")
resp.check(rcode="NOERROR", rdata="192.0.2.4")

# Test geo-dependent answers.
for i in range(1, 1000):
    random_client = "127.255." + str(random.randint(1, 250)) + ".0"
    resp = knot.dig("foo.example.com", "A", source=random_client)
    resp.check(rcode="NOERROR", rdata=random_client)
