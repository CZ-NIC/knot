#!/usr/bin/env python3

'''geoip module functionality test'''

from dnstest.test import Test
from dnstest.module import ModGeoip
from dnstest.utils import *
import random
import os
import shutil

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
subnet2_filename = knot.dir + "net2.conf"
subnet3_filename = knot.dir + "net3.conf"
geo_conf = open(geodb_filename, "w")
net_conf = open(subnet_filename, "w")
net2_conf = open(subnet2_filename, "w")
net3_conf = open(subnet3_filename, "w")
dname_count = 10
iso_count = len(iso_codes)
for i in range(1, dname_count + 1):
    print("d" + str(i) + ".example.com:", file=geo_conf)
    print("d" + str(i) + ".example.com:", file=net_conf)
    print("d" + str(i) + ".example.com:", file=net2_conf)
    print("d" + str(i) + ".example.com:", file=net3_conf)
    geo_id = 1
    for iso_code in iso_codes:
        print("  - geo: \"" + iso_code + ";" + str(geo_id) + "\"", file=geo_conf)
        print("    A: 127.255." + str(geo_id) + ".0", file=geo_conf)
        print("  - net: 127.255." + str(geo_id) + ".0/24", file=net_conf)
        print("    A: 127.255." + str(geo_id) + ".0", file=net_conf)
        print("  - net: 127.255." + str(geo_id) + ".0/24", file=net2_conf)
        print("    A: 126.255." + str(geo_id) + ".0", file=net2_conf)
        print("  - net: 127.255." + str(geo_id) + ".0/24", file=net3_conf)
        print("    A: 126.257." + str(geo_id) + ".0", file=net3_conf)
        geo_id += 1
geo_conf.close()
net_conf.close()
net2_conf.close()
net3_conf.close()

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
    middle = str(random.randint(1, iso_count))
    random_client = "127.255." + middle + ".0"
    resp = knot.dig("d" + str(random.randint(1, dname_count)) + ".example.com", "A", source=random_client)
    resp.check(rcode="NOERROR", rdata=random_client)

    # check NODATA response when querying different type
    resp = knot.dig("d" + str(random.randint(2, dname_count)) + ".example.com", "AAAA", source=random_client)
    resp.check(rcode="NOERROR")
    resp.check_count(1, "SOA", section="authority")

    # check that NODATA behaviour does not shadow existing RR in the zone
    resp = knot.dig("d1.example.com", "AAAA", source=random_client)
    resp.check(rcode="NOERROR", rdata="1::4")

# Restart with subnet module.
knot.clear_modules(zone)
knot.add_module(zone, mod_subnet);
knot.gen_confile()
knot.reload()
knot.zone_wait(zone)

# Test default answer again.
resp = knot.dig("foo.example.com", "A")
resp.check(rcode="NOERROR", rdata="192.0.2.4")

# Test subnet-dependent answers.
for i in range(1, 1000):
    middle = str(random.randint(1, iso_count))
    random_client = "127.255." + middle + ".0"
    resp = knot.dig("d" + str(random.randint(1, dname_count)) + ".example.com", "A", source=random_client)
    resp.check(rcode="NOERROR", rdata=random_client)

    resp = knot.dig("d" + str(random.randint(2, dname_count)) + ".example.com", "AAAA", source=random_client)
    resp.check(rcode="NOERROR")
    resp.check_count(1, "SOA", section="authority")

    resp = knot.dig("d1.example.com", "AAAA", source=random_client)
    resp.check(rcode="NOERROR", rdata="1::4")

# Switch subnet file.
#shutil.move(subnet2_filename, subnet_filename)
#knot.ctl("-f zone-reload example.com.", wait=True)
mod_subnet.config_file = subnet2_filename
knot.gen_confile()
knot.reload()
t.sleep(2)

# Test that dependent answers differ
for i in range(1, 1000):
    middle = str(random.randint(1, iso_count))
    random_client = "127.255." + middle + ".0"
    expected_rdata = "126.255." + middle + ".0"
    resp = knot.dig("d" + str(random.randint(1, dname_count)) + ".example.com", "A", source=random_client)
    resp.check(rcode="NOERROR", rdata=expected_rdata, nordata=random_client)

    resp = knot.dig("d" + str(random.randint(2, dname_count)) + ".example.com", "AAAA", source=random_client)
    resp.check(rcode="NOERROR")
    resp.check_count(1, "SOA", section="authority")

    resp = knot.dig("d1.example.com", "AAAA", source=random_client)
    resp.check(rcode="NOERROR", rdata="1::4")

# Attempt invalid subnet file.

mod_subnet.config_file = subnet3_filename
knot.gen_confile()
reload_failed = False
try:
    knot.reload()
except:
    reload_failed = True
if not reload_failed:
    set_err("Reload not failed")
t.sleep(2)

middle = str(random.randint(1, iso_count))
random_client = "127.255." + middle + ".0"
expected_rdata = "126.255." + middle + ".0"
resp = knot.dig("d" + str(random.randint(1, dname_count)) + ".example.com", "A", source=random_client)
resp.check(rcode="NOERROR", rdata=expected_rdata, nordata=random_client)
