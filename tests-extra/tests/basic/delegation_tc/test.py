"""
Tests for TC flag setting in delegations.
"""

from dnstest.test import Test

t = Test(stress=False)

knot = t.server("knot", tsig=False)
zone = t.zone("tc.test", storage=".")
t.link(zone, knot)

t.start()

def test_delegation(delegation, bufsize=None, truncated=False, counts=None):
    name = "www.%s" % delegation
    resp = knot.dig(name, "A", udp=True, dnssec=True, bufsize=bufsize)
    if truncated:
        flags = "TC"
        noflags = "AA"
    else:
        flags = ""
        noflags = "AA TC"

    resp.check(rcode="NOERROR", noflags=noflags, flags=flags)
    for section in counts:
        for rtype in counts[section]:
            resp.check_count(counts[section][rtype], rtype, section)

## delegation with glue

# incomplete delegation, no DS
test_delegation("glue.tc.test", bufsize=512, truncated=True, counts={
    "authority": {"NS": 2, "DS": 0, "RRSIG": 0},
    "additional": {"AAAA": 0, "RRSIG": 0}}
)
# incomplete delegation, no glue
test_delegation("glue.tc.test", bufsize=712, truncated=True, counts={
    "authority": {"NS": 2, "DS": 1, "RRSIG": 1},
    "additional": {"AAAA": 0, "RRSIG": 0}}
)
# incomplete delegation, partial glue
test_delegation("glue.tc.test", bufsize=740, truncated=True, counts={
    "authority": {"NS": 2, "DS": 1, "RRSIG": 1},
    "additional": {"AAAA": 1, "RRSIG": 0}}
)
# complete delegation, complete glue
test_delegation("glue.tc.test", bufsize=768, truncated=False, counts={
    "authority": {"NS": 2, "DS": 1, "RRSIG": 1},
    "additional": {"AAAA": 2, "RRSIG": 0}}
)

## unreachable delegation due to missing glue

# incomplete delegation, no DS
test_delegation("unreachable.tc.test", bufsize=512, truncated=True, counts={
    "authority": {"NS": 2, "DS": 0, "RRSIG": 0},
    "additional": {"AAAA": 0, "RRSIG": 0}}
)
# complete delegation, no glue available
test_delegation("unreachable.tc.test", bufsize=719, truncated=False, counts={
    "authority": {"NS": 2, "DS": 1, "RRSIG": 1},
    "additional": {"AAAA": 0, "RRSIG": 0}}
)

## delegation with foreign name servers

# incomplete delegation, no DS
test_delegation("foreign.tc.test", bufsize=512, truncated=True, counts={
    "authority": {"NS": 2, "DS": 0, "RRSIG": 0},
    "additional": {"AAAA": 0, "RRSIG": 0}}
)
# complete delegation, no glue needed
test_delegation("unreachable.tc.test", bufsize=722, truncated=False, counts={
    "authority": {"NS": 2, "DS": 1, "RRSIG": 1},
    "additional": {"AAAA": 0, "RRSIG": 0}}
)

## delegation with name servers from parent

# incomplete delegation, no DS
test_delegation("parent.tc.test", bufsize=512, truncated=True, counts={
    "authority": {"NS": 2, "DS": 0, "RRSIG": 0},
    "additional": {"AAAA": 0, "RRSIG": 0}}
)
# complete delegation, no optional additionals
test_delegation("parent.tc.test", bufsize=714, truncated=False, counts={
    "authority": {"NS": 2, "DS": 1, "RRSIG": 1},
    "additional": {"AAAA": 0, "RRSIG": 0}}
)
# complete delegation, one optional additional
test_delegation("parent.tc.test", bufsize=742, truncated=False, counts={
    "authority": {"NS": 2, "DS": 1, "RRSIG": 1},
    "additional": {"AAAA": 1, "RRSIG": 0}}
)
# complete delegation, all optional additionals without signatures
test_delegation("parent.tc.test", bufsize=770, truncated=False, counts={
    "authority": {"NS": 2, "DS": 1, "RRSIG": 1},
    "additional": {"AAAA": 2, "RRSIG": 0}}
)
# complete delegation, all optional additionals partially signed
test_delegation("parent.tc.test", bufsize=873, truncated=False, counts={
    "authority": {"NS": 2, "DS": 1, "RRSIG": 1},
    "additional": {"AAAA": 2, "RRSIG": 1}}
)
# complete delegation, all optional additionals with signatures
test_delegation("parent.tc.test", bufsize=976, truncated=False, counts={
    "authority": {"NS": 2, "DS": 1, "RRSIG": 1},
    "additional": {"AAAA": 2, "RRSIG": 2}}
)

t.stop()
