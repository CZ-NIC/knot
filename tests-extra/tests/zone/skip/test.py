#!/usr/bin/env python3

'''Test of zonefile-skip.'''

from dnstest.test import Test

t = Test()

server = t.server("knot")
zone = t.zone("example.com.")

t.link(zone, server)

server.dnssec(zone).enable = True

server.conf_zone(zone).zonefile_skip = [ "aaaa", "dnssec" ]

t.start()

server.zone_wait(zone)
zf = server.zones[zone[0].name].zfile

resp = server.dig("dns1.example.com.", "A", dnssec=True)
resp.check_count(1, "A")
resp.check_count(1, "RRSIG")
resp = server.dig("dns1.example.com.", "AAAA", dnssec=True)
resp.check_count(0, "AAAA")

up = server.update(zone)
up.add("dns4", 3600, "A", "192.0.2.4")
up.add("dns4", 3600, "AAAA", "2001:DB8::4")
up.send("NOERROR")

resp = server.dig("dns4.example.com.", "AAAA", dnssec=True)
resp.check_count(1, "AAAA")

server.ctl("zone-flush", wait=True)
zf.check_count(0, "AAAA")
zf.check_count(0, "RRSIG")
zf.check_count(0, "NSEC")

server.conf_zone(zone).zonefile_skip = [ "a", "nsec" ]
server.gen_confile()
server.reload()
t.sleep(2)
zf.update_soa()
server.ctl("zone-reload", wait=True)

resp = server.dig("dns1.example.com.", "A", dnssec=True)
resp.check_count(0, "A")

up = server.update(zone)
up.add("dns5", 3600, "A", "192.0.2.5")
up.add("dns5", 3600, "AAAA", "2001:DB8::5")
up.send("NOERROR")

resp = server.dig("dns5.example.com.", "A", dnssec=True)
resp.check_count(1, "A")

server.ctl("zone-flush", wait=True)
zf.check_count(0, "A")
zf.check_count(1, "AAAA")
zf.check_count(10, "RRSIG")
zf.check_count(0, "NSEC")

server.conf_zone(zone).zonefile_sync = "-1"
server.conf_zone(zone).zonefile_load = "difference-no-serial"
server.conf_zone(zone).journal_content = "all"
server.gen_confile()
server.reload()
t.sleep(1)
server.ctl("zone-reload", wait=True)

up = server.update(zone)
up.add("dns6", 3600, "A", "192.0.2.6")
up.add("dns6", 3600, "AAAA", "2001:DB8::6")
up.send("NOERROR")

zf.append_rndAAAA("zf", 0xdead, 0xbeef)
server.ctl("zone-reload", wait=True)

resp = server.dig("dns6.example.com.", "A", dnssec=True)
resp.check_count(1, "A")
resp = server.dig("dns6.example.com.", "AAAA", dnssec=True)
resp.check_count(0, "AAAA")
resp = server.dig("zf.example.com.", "AAAA", dnssec=True)
resp.check_count(1, "AAAA")

server.ctl("-f zone-purge +expire example.com.")
t.sleep(1)
try:
    server.ctl("zone-flush +outdir " + server.data_dir, wait=True)
except:
    pass # just checking that server does not crash, below:
server.ctl("zone-status")

t.end()
