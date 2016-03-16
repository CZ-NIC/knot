#!/usr/bin/env python3

'''Test for DDNS prerequisites'''

from dnstest.test import Test

t = Test()

srv = t.server("knot")
zone = t.zone("ddns.", storage=".")

t.link(zone, srv, ddns=True)

t.start()

# PREREQ YXDOMAIN
# ===============
# OK
update = srv.update(zone)
update.prereq_yx("existing.ddns.")
update.add("1.ddns.", 1, "TXT", "text")
update.send("NOERROR")
resp = srv.dig("1.ddns.", "TXT")
resp.check("text")

# OK in apex
update = srv.update(zone)
update.prereq_yx("ddns.")
update.add("2.ddns.", 1, "TXT", "text")
update.send("NOERROR")
resp = srv.dig("2.ddns.", "TXT")
resp.check("text")

# NAME not in zone
update = srv.update(zone)
update.prereq_yx("notexisting.ddns.")
update.add("3.ddns.", 1, "TXT", "text")
update.send("NXDOMAIN")
resp = srv.dig("3.ddns.", "TXT")
resp.check(rcode="NXDOMAIN")

# NAME out of zone
update = srv.update(zone)
update.prereq_yx("notexisting.")
update.add("4.ddns.", 1, "TXT", "text")
update.send("NOTZONE")
resp = srv.dig("4.ddns.", "TXT")
resp.check(rcode="NXDOMAIN")

# PREREQ NXDOMAIN
# ===============
# OK
update = srv.update(zone)
update.prereq_nx("notexisting.ddns.")
update.add("4.ddns.", 1, "TXT", "text")
update.send("NOERROR")
resp = srv.dig("4.ddns.", "TXT")
resp.check("text")

# NAME in zone
update = srv.update(zone)
update.prereq_nx("existing.ddns.")
update.add("5.ddns.", 1, "TXT", "text")
update.send("YXDOMAIN")
resp = srv.dig("5.ddns.", "TXT")
resp.check(rcode="NXDOMAIN")

# NAME out of zone
update = srv.update(zone)
update.prereq_nx("notexisting.")
update.add("6.ddns.", 1, "TXT", "text")
update.send("NOTZONE")
resp = srv.dig("6.ddns.", "TXT")
resp.check(rcode="NXDOMAIN")

# PREREQ NXRRSET
# ==============
# OK - neither NAME nor TYPE in zone
update = srv.update(zone)
update.prereq_nx("notexisting.ddns.", "TYPE65535")
update.add("7.ddns.", 1, "TXT", "text")
update.send("NOERROR")
resp = srv.dig("7.ddns.", "TXT")
resp.check("text")

# OK - TYPE not in zone
update = srv.update(zone)
update.prereq_nx("existing.ddns.", "TYPE65535")
update.add("8.ddns.", 1, "TXT", "text")
update.send("NOERROR")
resp = srv.dig("8.ddns.", "TXT")
resp.check("text")

# RRSET in zone
update = srv.update(zone)
update.prereq_nx("existing.ddns.", "A")
update.add("9.ddns.", 1, "TXT", "text")
update.send("YXRRSET")
resp = srv.dig("9.ddns.", "TXT")
resp.check(rcode="NXDOMAIN")

# NAME out of zone
update = srv.update(zone)
update.prereq_nx("notexisting.", "TYPE65535")
update.add("10.ddns.", 1, "TXT", "text")
update.send("NOTZONE")
resp = srv.dig("10.ddns.", "TXT")
resp.check(rcode="NXDOMAIN")

# OK - wildcard + TYPE not in zone
update = srv.update(zone)
update.prereq_nx("a.wildcard.ddns.", "TYPE65535")
update.add("11.ddns.", 1, "TXT", "text")
update.send("NOERROR")
resp = srv.dig("11.ddns.", "TXT")
resp.check("text")

# OK - wildcard
update = srv.update(zone)
update.prereq_nx("a.wildcard.ddns.", "A")
update.add("12.ddns.", 1, "TXT", "text")
update.send("NOERROR")
resp = srv.dig("12.ddns.", "TXT")
resp.check("text")

# Exact wildcard
update = srv.update(zone)
update.prereq_nx("*.wildcard.ddns.", "A")
update.add("13.ddns.", 1, "TXT", "text")
update.send("YXRRSET")
resp = srv.dig("13.ddns.", "TXT")
resp.check(rcode="NXDOMAIN")

# PREREQ YXRRSET
# ==============
# Neither NAME nor TYPE in zone
update = srv.update(zone)
update.prereq_yx("notexisting.ddns.", "TYPE65535")
update.add("13.ddns.", 1, "TXT", "text")
update.send("NXRRSET")
resp = srv.dig("13.ddns.", "TXT")
resp.check(rcode="NXDOMAIN")

# TYPE not in zone
update = srv.update(zone)
update.prereq_yx("existing.ddns.", "TYPE65535")
update.add("14.ddns.", 1, "TXT", "text")
update.send("NXRRSET")
resp = srv.dig("14.ddns.", "TXT")
resp.check(rcode="NXDOMAIN")

# OK - RRSET in zone
update = srv.update(zone)
update.prereq_yx("existing.ddns.", "A")
update.add("15.ddns.", 1, "TXT", "text")
update.send("NOERROR")
resp = srv.dig("15.ddns.", "TXT")
resp.check("text")

# OK - RRSET and RDATA in zone
update = srv.update(zone)
update.prereq_yx("existing.ddns.", "A", "1.2.3.4")
update.add("16.ddns.", 1, "TXT", "text")
update.send("NOERROR")
resp = srv.dig("16.ddns.", "TXT")
resp.check("text")

# RDATA not in zone
update = srv.update(zone)
update.prereq_yx("existing.ddns.", "A", "1.2.3.255")
update.add("17.ddns.", 1, "TXT", "text")
update.send("NXRRSET")
resp = srv.dig("17.ddns.", "TXT")
resp.check(rcode="NXDOMAIN")

# NAME out of zone
update = srv.update(zone)
update.prereq_yx("notexisting.", "TYPE65535")
update.add("18.ddns.", 1, "TXT", "text")
update.send("NOTZONE")
resp = srv.dig("18.ddns.", "TXT")
resp.check(rcode="NXDOMAIN")

# Wildcard + TYPE not in zone
update = srv.update(zone)
update.prereq_yx("a.wildcard.ddns.", "TYPE65535")
update.add("19.ddns.", 1, "TXT", "text")
update.send("NXRRSET")
resp = srv.dig("19.ddns.", "TXT")
resp.check(rcode="NXDOMAIN")

# Wildcard
update = srv.update(zone)
update.prereq_yx("a.wildcard.ddns.", "A")
update.add("20.ddns.", 1, "TXT", "text")
update.send("NXRRSET")
resp = srv.dig("20.ddns.", "TXT")
resp.check(rcode="NXDOMAIN")

# OK - exact wildcard
update = srv.update(zone)
update.prereq_yx("*.wildcard.ddns.", "A")
update.add("21.ddns.", 1, "TXT", "text")
update.send("NOERROR")
resp = srv.dig("21.ddns.", "TXT")
resp.check("text")

t.end()
