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
resp.check_record(section="answer", rtype="A", ttl="1000", rdata="192.0.2.3")
resp.check_record(section="answer", rtype="A", ttl="1000", rdata="1.2.3.4")

# Try to add two RRs belonging to one RRSet, but with different TTLs
# The UPDATE should be REFUSED
# This also tests rollback in case of addition

check_log("Add RRSet with incoherent TTLs")
up = master.update(zone)
up.add("test.example.com.", 1000, "A", "1.2.3.4")
up.add("test.example.com.", 2000, "A", "2.3.4.5")
up.send("REFUSED")
resp = master.dig("test.example.com.", "A")

# First, delete RRSet already in zone, then add new RR with different TTL
# The UPDATE should be accepted and the new RR should be present in the zone

check_log("Delete RRSet from zone + add new RR with different TTL instead")
up = master.update(zone)
up.delete("mail.example.com.", "A")
up.add("mail.example.com.", 1000, "A", "1.2.3.4")
up.send("NOERROR")
resp = master.dig("mail.example.com.", "ANY")
resp.check_record(section="answer", rtype="A", ttl="1000", rdata="1.2.3.4")
resp.check_record(section="answer", rtype="A", nordata="192.0.2.3")
resp.check_record(section="answer", rtype="AAAA", ttl="3600", rdata="2001:db8::3")

# Some prerequisities for the next test
up = master.update(zone)
up.add("test2.example.com.", 3600, "A", "1.2.3.4")
up.add("test2.example.com.", 3600, "A", "2.3.4.5")
up.send("NOERROR")

# Delete one of RRs in a zone RRSet, then add new RR with different TTL
# The UPDATE should be accepted, old TTLs shall change to the new value

check_log("Delete one RR from a RRSet + try to add RR with different TTL instead")
up = master.update(zone)
up.delete("test2.example.com.", "A", "1.2.3.4")
up.add("test2.example.com.", 1000, "A", "3.4.5.6")
up.send("NOERROR")
resp = master.dig("test2.example.com.", "A")
resp.check_record(section="answer", rtype="A", nordata="1.2.3.4")
resp.check_record(section="answer", rtype="A", ttl="1000", rdata="3.4.5.6")

# Test for rollback - a lot of changes and an invalid RR

check_log("Rollback test: a lot of changes")
up = master.update(zone)
# Add to existing RRSet
up.add("test2.example.com.", 3600 , "A", "3.4.5.6")
up.add("test2.example.com.", 3600 , "A", "3.4.5.7")
# Add new RRSet to an existing node
up.add("test2.example.com.", 1000, "MX", "10 somewhere.com.");
# Add new node
up.add("test3.example.com.", 2000, "A", "5.6.7.8")
# Remove specific RR
up.delete("test2.example.com.", "A", "1.2.3.4")
# Remove whole RRSet
up.delete("mail.example.com.", "A")
# Remove whole node
up.delete("dns1.example.com.", "ANY")
# Add invalid RR so that the UPDATE is refused
up.prereq_yx("notexisting.com.")
up.delete("test2.notexisting.com.", "A", "7.8.9.0")
up.send("NOTZONE")

resp = master.dig("test2.example.com.", "ANY")
resp.check_record(section="answer", rtype="A", nordata="1.2.3.4")
resp.check_record(section="answer", rtype="A", ttl="1000", rdata="2.3.4.5")
resp.check_record(section="answer", rtype="A", ttl="1000", rdata="3.4.5.6")
resp.check_record(section="answer", rtype="MX", nordata="10 somewhere.com.")
resp.check_record(section="answer", rtype="A", nordata="7.8.9.0")

resp = master.dig("test3.example.com", "ANY")
resp.check(rcode="NXDOMAIN")

resp = master.dig("mail.example.com.", "ANY")
resp.check_record(section="answer", rtype="A", ttl="1000", rdata="1.2.3.4")
resp.check_record(section="answer", rtype="AAAA", ttl="3600", rdata="2001:db8::3")

resp = master.dig("dns1.example.com.", "ANY")
resp.check_record(section="answer", rtype="A", ttl="3600", rdata="192.0.2.1")
resp.check_record(section="answer", rtype="AAAA", ttl="3600", rdata="2001:db8::1")

t.end()

