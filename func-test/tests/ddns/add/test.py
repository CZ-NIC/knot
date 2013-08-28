#!/usr/bin/env python3

''' '''

import dnstest

t = dnstest.DnsTest()

master = t.server("knot")
zone = t.zone("example.com.", "example.com.zone")

t.link(zone, master, ddns=True)

t.start()

update = master.update(zone)
update.add("t1.example.com.", 1234, "A", "1.2.3.4")
update.add("t2.example.com.", 1234, "A", "1.2.3.4")
update.add("t3.example.com.", 1234, "A", "1.2.3.4")
update.send()
update.delete("t2.example.com.")
update.send()

t.stop()
