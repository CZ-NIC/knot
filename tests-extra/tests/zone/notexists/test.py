#!/usr/bin/env python3

'''Test for loading non-existing zone file'''

from dnstest.test import Test

def run_test():
    t = Test()

    master = t.server("knot")

    zones = t.zone("notexist.", exists=False) + t.zone("example.com.")

    t.link(zones, master)

    t.start()

    # Check if the server is answering and zone _isn't_ loaded
    resp = master.dig("notexist.", "SOA", udp=True)
    resp.check(rcode="SERVFAIL") # Unloadable zone, but in the zone database

    # Check if the server is answering and zone is unknown
    resp = master.dig("xfiles.", "SOA", udp=True)
    resp.check(rcode="REFUSED")

    # The other zone should answer without problem
    resp = master.dig("example.com.", "SOA", udp=True)
    resp.check(rcode="NOERROR")

    # Stop master.
    master.stop()

    t.end()
