#!/usr/bin/env python3

'''Test mixing TTLS within journal operation.'''

from dnstest.test import Test

t = Test()

master = t.server("knot")

zones = t.zone("example.")

t.link(zones, master)

master.dnssec(zones).enable = True
master.dnssec(zones).dnskey_management = "incremental"
master.dnssec(zones).delete_delay = 20
master.dnssec(zones).dnskey_ttl = 100
master.conf_zone(zones).zonefile_load = "difference"

t.start()
serial = master.zones_wait(zones)

for z in zones:
    master.ctl("zone-flush " + z.name, wait=True)
    master.zones[z.name].zfile.update_soa()
    master.zones[z.name].zfile.append_rndDNSKEY(200)

master.ctl("zone-reload")
serial = master.zones_wait(zones, serial)

for z in zones:
    master.ctl("zone-key-rollover %s zsk" % z.name)
serial = master.zones_wait(zones, serial)
#master.ctl("zone-flush", wait=True)

master.stop()

if True:
    for z in zones:
        master.zones[z.name].zfile.update_soa()
        master.zones[z.name].zfile.append_rndDNSKEY(200)

master.start()

master.zones_wait(zones, serial, equal=True)

t.end()
