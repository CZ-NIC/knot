#!/usr/bin/env python3

'''geoip module functionality test'''

from dnstest.test import Test
from dnstest.module import ModGeoip
from dnstest.utils import *
import random
import os

iso_codes = ['AD', 'AE', 'AF', 'AG', 'AI', 'AL', 'AM', 'AO', 'AQ', 'AR', 'AS', 'AT',
             'AU', 'AW', 'AX', 'AZ', 'BA', 'BB', 'BD', 'BE', 'BF', 'BG', 'BH', 'BI',
             'BJ', 'BL', 'BM', 'BN', 'BO', 'BQ', 'BQ', 'BR', 'BS', 'BT', 'BV', 'BW',
             'BY', 'BZ', 'CA', 'CC', 'CD', 'CF', 'CG', 'CH', 'CI', 'CK', 'CL', 'CM',
             'CN', 'CO', 'CR', 'CU', 'CV', 'CW', 'CX', 'CY', 'CZ', 'DE', 'DJ', 'DK',
             'DM', 'DO', 'DZ', 'EC', 'EE', 'EG', 'EH', 'ER', 'ES', 'ET', 'FI', 'FJ',
             'FK', 'FM', 'FO', 'FR', 'GA', 'GB', 'GD', 'GE', 'GF', 'GG', 'GH', 'GI',
             'GL', 'GM', 'GN', 'GP', 'GQ', 'GR', 'GS', 'GT', 'GU', 'GW', 'GY', 'HK',
             'HM', 'HN', 'HR', 'HT', 'HU', 'ID', 'IE', 'IL', 'IM', 'IN', 'IO', 'IQ',
             'IR', 'IS', 'IT', 'JE', 'JM', 'JO', 'JP', 'KE', 'KG', 'KH', 'KI', 'KM',
             'KN', 'KP', 'KR', 'KW', 'KY', 'KZ', 'LA', 'LB', 'LC', 'LI', 'LK', 'LR',
             'LS', 'LT', 'LU', 'LV', 'LY', 'MA', 'MC', 'MD', 'ME', 'MF', 'MG', 'MH',
             'MK', 'ML', 'MM', 'MN', 'MO', 'MP', 'MQ', 'MR', 'MS', 'MT', 'MU', 'MV',
             'MW', 'MX', 'MY', 'MZ', 'NA', 'NC', 'NE', 'NF', 'NG', 'NI', 'NL', 'NO',
             'NP', 'NR', 'NU', 'NZ', 'OM', 'PA', 'PE', 'PF', 'PG', 'PH', 'PK', 'PL',
             'PM', 'PN', 'PR', 'PS', 'PT', 'PW', 'PY', 'QA', 'RE', 'RO', 'RS', 'RU',
             'RW', 'SA', 'SB', 'SC', 'SD', 'SE', 'SG', 'SH', 'SI', 'SJ', 'SK', 'SL',
             'SM', 'SN', 'SO', 'SR', 'SS', 'ST', 'SV', 'SX', 'SY', 'SZ', 'TC', 'TD',
             'TF', 'TG', 'TH', 'TJ', 'TK', 'TL', 'TM', 'TN', 'TO', 'TR', 'TT', 'TV',
             'TW', 'TZ', 'UA', 'UG', 'UM', 'US', 'UY', 'UZ', 'VA', 'VC', 'VE', 'VG',
             'VI', 'VN', 'VU', 'WF', 'WS', 'YE', 'YT', 'ZA', 'ZM', 'ZW'];

t = Test(address=4, stress=False)
knot = t.server("knot")

zone = t.zone("example.com.", storage=".")
t.link(zone, knot)

# Generate configuration files for geoip module.
geodb_filename = knot.dir + "geo.conf"
subnet_filename = knot.dir + "net.conf"
geo_conf = open(geodb_filename, "w")
net_conf = open(subnet_filename, "w")
dname_count = 10
iso_count = len(iso_codes)
for i in range(1, dname_count + 1):
    print("d" + str(i) + ".example.com:", file=geo_conf)
    print("d" + str(i) + ".example.com:", file=net_conf)
    geo_id = 1
    for iso_code in iso_codes:
        print("  - geo: \"" + iso_code + ";" + str(geo_id) + "\"", file=geo_conf)
        print("    A: 127.255." + str(geo_id) + ".0", file=geo_conf)
        print("  - net: 127.255." + str(geo_id) + ".0/24", file=net_conf)
        print("    A: 127.255." + str(geo_id) + ".0", file=net_conf)
        geo_id += 1
geo_conf.close()
net_conf.close()

ModGeoip.check()

mod_geoip = ModGeoip(geodb_filename, "geodb", t.data_dir + "db.mmdb",
                     ["country/iso_code", "(id)city/geoname_id"])
mod_subnet = ModGeoip(subnet_filename)

knot.add_module(zone, mod_geoip);

t.start()

knot.zone_wait(zone)

# Test default answer.
resp = knot.dig("foo.example.com", "A")
resp.check(rcode="NOERROR", rdata="192.0.2.4")

# Test geo-dependent answers.
for i in range(1, 1000):
    random_client = "127.255." + str(random.randint(1, iso_count)) + ".0"
    resp = knot.dig("d" + str(random.randint(1, dname_count)) + ".example.com", "A", source=random_client)
    resp.check(rcode="NOERROR", rdata=random_client)

# Restart with subnet module.
knot.clear_modules(None)
knot.add_module(zone, mod_subnet);
knot.gen_confile()
knot.reload()
knot.zone_wait(zone)

# Test default answer again.
resp = knot.dig("foo.example.com", "A")
resp.check(rcode="NOERROR", rdata="192.0.2.4")

# Test subnet-dependent answers.
for i in range(1, 1000):
    random_client = "127.255." + str(random.randint(1, iso_count)) + ".0"
    resp = knot.dig("d" + str(random.randint(1, dname_count)) + ".example.com", "A", source=random_client)
    resp.check(rcode="NOERROR", rdata=random_client)

os.remove(geodb_filename)
os.remove(subnet_filename)
