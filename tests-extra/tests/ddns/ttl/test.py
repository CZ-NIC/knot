#!/usr/bin/env python3

'''TTL mismatch test'''

from dnstest.utils import *
from dnstest.test import Test

t = Test()

zone = t.zone("example.com.")

master = t.server("knot")
t.link(zone, master, ddns=True)

t.start()

# Add new RR with different TTL to a RRSet that is already in the zone
# The UPDATE should be accepted and all previous TTLs should change to be the same value

check_log("Add RR with different TTL")
up = master.update(zone)
up.add("mail.example.com.", 1000, "A", "1.2.3.4")
up.send("NOERROR")
resp = master.dig("mail.example.com.", "A")
resp.check(rcode="NOERROR")
resp.check_record(section="answer", rtype="A", ttl="1000", rdata="192.0.2.3")
resp.check_record(section="answer", rtype="A", ttl="1000", rdata="1.2.3.4")

# Try to add two RRs belonging to one RRSet, but with different TTLs
# The UPDATE should be accepted and all TTLs should change to be the same value

check_log("Add RRSet with incoherent TTLs")
up = master.update(zone)
up.add("test.example.com.", 1000, "A", "1.2.3.4")
up.add("test.example.com.", 2000, "A", "2.3.4.5")
up.send("NOERROR")
resp = master.dig("test.example.com.", "A")
resp.check(rcode="NOERROR")
resp.check_record(section="answer", rtype="A", ttl="2000", rdata="1.2.3.4")
resp.check_record(section="answer", rtype="A", ttl="2000", rdata="2.3.4.5")

# First, delete RRSet already in zone, then add new RR with different TTL
# The UPDATE should be accepted and the new RR should be present in the zone

check_log("Delete RRSet from zone + add new RR with different TTL instead")
up = master.update(zone)
up.delete("mail.example.com.", "A")
up.add("mail.example.com.", 1000, "A", "1.2.3.4")
up.send("NOERROR")
resp = master.dig("mail.example.com.", "ANY")
resp.check(rcode="NOERROR")
resp.check_record(section="answer", rtype="A", ttl="1000", rdata="1.2.3.4")
resp.check_record(section="answer", rtype="A", nordata="192.0.2.3")
resp.check_record(section="answer", rtype="AAAA", ttl="3600", rdata="2001:db8::3")

t.end()

