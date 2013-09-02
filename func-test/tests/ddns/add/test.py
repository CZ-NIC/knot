#!/usr/bin/env python3

'''Test for DDNS - add record'''

import dnstest

t = dnstest.DnsTest()

srv = t.server("bind")
zone = t.zone("example.com.", "example.com.zone")

t.link(zone, srv, ddns=True)

t.start()

update = srv.update(zone)

# Add one record.
update.add("test1.example.com.", 1234, "A", "1.2.3.4")
update.send()
resp = srv.dig("test1.example.com.", "A")
resp.check("1.2.3.4", 1234)

# Add more records including glue record.
update.add("test2.example.com.", 1234, "NS", "test2.sub.example.com.")
update.add("test2.sub.example.com.", 2222, "A", "1.2.3.4")
update.send()
resp_a = srv.dig("test2.sub.example.com.", "A")
resp_a.check("1.2.3.4", 2222)

t.stop()
