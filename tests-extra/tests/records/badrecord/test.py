#!/usr/bin/env python3

''' Test for loading badly formed record '''

from dnstest.test import Test

t = Test()

master = t.server("knot")

zone = t.zone("badrecord.", "badrecord.zone", storage=".")

t.link(zone, master)

t.start()

# Check if the server is answering and zone _isn't_ loaded
resp = master.dig("badrecord.", "SOA", udp=True)
resp.check(rcode="REFUSED")

# Stop master.
master.stop()

t.end()
