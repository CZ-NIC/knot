#!/usr/bin/env python3

'''Test of DNSKEY-DDS feature.'''

from dnstest.test import Test
from dnstest.utils import *

t = Test()

def check_zone(server, zone, dnskeys, dnskey_rrsigs, cdnskeys, cdss, soa_rrsigs, msg):
    qdnskeys = server.dig("example.com", "DNSKEY", bufsize=4096)
    found_dnskeys = qdnskeys.count("DNSKEY")

    qdnskeyrrsig = server.dig("example.com", "DNSKEY", dnssec=True, bufsize=4096)
    found_rrsigs = qdnskeyrrsig.count("RRSIG")

    qcdnskey = server.dig("example.com", "CDNSKEY", bufsize=4096)
    found_cdnskeys = qcdnskey.count("CDNSKEY")
    
    qcds = server.dig("example.com", "CDS", bufsize=4096)
    found_cdss = qcds.count("CDS")

    qsoa = server.dig("example.com", "SOA", dnssec=True, bufsize=4096)
    found_soa_rrsigs = qsoa.count("RRSIG")

    check_log("DNSKEYs: %d (expected %d)" % (found_dnskeys, dnskeys));
    check_log("RRSIGs: %d (expected %d)" % (found_soa_rrsigs, soa_rrsigs));
    check_log("DNSKEY-RRSIGs: %d (expected %d)" % (found_rrsigs, dnskey_rrsigs));
    check_log("CDNSKEYs: %d (expected %d)" % (found_cdnskeys, cdnskeys));
    check_log("CDSs: %d (expected %d)" % (found_cdss, cdss));

    if found_dnskeys != dnskeys:
        set_err("BAD DNSKEY COUNT: " + msg)
        detail_log("!DNSKEYs not published and activated as expected: " + msg)

    if found_soa_rrsigs != soa_rrsigs:
        set_err("BAD RRSIG COUNT: " + msg)
        detail_log("!RRSIGs not published and activated as expected: " + msg)

    if found_rrsigs != dnskey_rrsigs:
        set_err("BAD DNSKEY RRSIG COUNT: " + msg)
        detail_log("!RRSIGs not published and activated as expected: " + msg)

    if found_cdnskeys != cdnskeys:
        set_err("BAD CDNSKEY COUNT: " + msg)
        detail_log("!CDNSKEYs not published and activated as expected: " + msg)

    if found_cdss != cdss:
        set_err("BAD CDS COUNT: " + msg)
        detail_log("!CDSs not published and activated as expected: " + msg)

    detail_log(SEP)

    server.zone_backup(zone, flush=True)
    server.zone_verify(zone)

master = t.server("knot")
zone = t.zone("example.com.")
master.key_ddns = True

t.link(zone, master, ddns=True)
master.dnssec(zone[0]).enable = True

t.start()

s = master.zones_wait(zone)

up = master.update(zone)
up.add("example.com.", 1, "TXT", "txt")
try:
    up.send("NOTAUTH") # refuse any other DDNS
except:
    pass # it may fail when TSIG expected at the response

check_zone(master, zone, 2, 1, 1, 1, 1, "initial check")

# add public-only KSK through DDNS
up = master.update(zone)
up.add("example.com.", 3600, "DNSKEY", "257 3 13 AGjNpWD+d/4Kwc0CHtdyWDmPraZl2xXdlO1fosNkatI3Yw8Scpl7akE+wdKEhRiBojRLYqWTQ4SHElxv5pPKGA==")
up.send("NOERROR")
s = master.zones_wait(zone, s)
check_zone(master, zone, 3, 1, 1, 1, 1, "add KSK")

# add CDS+CDNSKEY by DDNSing CDNSKEY
up = master.update(zone)
up.add("example.com.", 0, "CDNSKEY", "257 3 13 AGjNpWD+d/4Kwc0CHtdyWDmPraZl2xXdlO1fosNkatI3Yw8Scpl7akE+wdKEhRiBojRLYqWTQ4SHElxv5pPKGA==")
up.send("NOERROR")
s = master.zones_wait(zone, s)
check_zone(master, zone, 3, 1, 2, 2, 1, "add CDNSKEY")

# remove the KSK, effectively removing also CDNSKEY+CDS
up = master.update(zone)
up.delete("example.com.", "DNSKEY", "257 3 13 AGjNpWD+d/4Kwc0CHtdyWDmPraZl2xXdlO1fosNkatI3Yw8Scpl7akE+wdKEhRiBojRLYqWTQ4SHElxv5pPKGA==")
up.send("NOERROR")
s = master.zones_wait(zone, s)
check_zone(master, zone, 2, 1, 1, 1, 1, "remove KSK")

# add DNSKEY+CDNSKEY+CDS by DDNSing DNSKEY+CDS at once, with different algorithm
up = master.update(zone)
up.add("example.com.", 2, "DNSKEY", "257 3 14 uN90Rfdxl6JyYBd2B79ygxEEEZlIalo8iZchE0b+7b268DhV+0KvGJLaxPkddFOfUWAZ70KRTBF9fNiBFEMaT3C8br96QBQesHHlGi/MAI6O0iC3zqbuhXgWlJC3CQSF")
up.add("example.com.", 0, "CDS", "46789 14 2 6AD97AA3C827CFFF1186F306D6690BBD0FC1FDADA84A3CFBEDECA41AEF59B067")
up.send("NOERROR")
s = master.zones_wait(zone, s)
check_zone(master, zone, 3, 1, 2, 2, 1, "add DNSKEY+CDS")

# remove the CDS
up = master.update(zone)
up.delete("example.com.", "CDS", "46789 14 2 6AD97AA3C827CFFF1186F306D6690BBD0FC1FDADA84A3CFBEDECA41AEF59B067")
up.send("NOERROR")
s = master.zones_wait(zone, s)
check_zone(master, zone, 3, 1, 1, 1, 1, "remove CDS")

# remove last KSK
up = master.update(zone)
up.delete("example.com.", "DNSKEY", "257 3 14 uN90Rfdxl6JyYBd2B79ygxEEEZlIalo8iZchE0b+7b268DhV+0KvGJLaxPkddFOfUWAZ70KRTBF9fNiBFEMaT3C8br96QBQesHHlGi/MAI6O0iC3zqbuhXgWlJC3CQSF")
up.send("NOERROR")
s = master.zones_wait(zone, s)
check_zone(master, zone, 2, 1, 1, 1, 1, "remove KSK")

t.end()
