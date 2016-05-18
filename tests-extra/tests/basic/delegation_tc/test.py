"""
Tests for TC flag setting in delegations.
"""

from dnstest.test import Test

t = Test()

knot = t.server("knot", tsig=False)
zone = t.zone("tc.test", storage=".")
t.link(zone, knot)

t.start()

class DelegationTest:
    def __init__(self, name):
        self._name = name

    def _get_flags(self, truncated):
        if truncated:
            return ("TC", "AA")
        else:
            return ("", "AA TC")

    def run(self, bufsize=None, truncated=False, counts=None):
        name = "www.%s" % self._name
        flags, noflags = self._get_flags(truncated)
        resp = knot.dig(name, "A", udp=True, dnssec=True, bufsize=bufsize)
        resp.check(rcode="NOERROR", noflags=noflags, flags=flags)
        for section in counts:
            for rtype in counts[section]:
                resp.check_count(counts[section][rtype], rtype, section)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_vaue, traceback):
        return False

# Delegation with glue

with DelegationTest("glue.tc.test") as test:
    # incomplete delegation, no DS
    test.run(bufsize=512, truncated=True, counts={
        "authority": {"NS": 2, "DS": 0, "RRSIG": 0},
        "additional": {"AAAA": 0, "RRSIG": 0}}
    )
    # incomplete delegation, DS without signature
    test.run(bufsize=665, truncated=True, counts={
        "authority": {"NS": 2, "DS": 1, "RRSIG": 0},
        "additional": {"AAAA": 0, "RRSIG": 0}}
    )
    # incomplete delegation, no glue
    test.run(bufsize=712, truncated=True, counts={
        "authority": {"NS": 2, "DS": 1, "RRSIG": 1},
        "additional": {"AAAA": 0, "RRSIG": 0}}
    )
    # incomplete delegation, partial glue
    test.run(bufsize=740, truncated=True, counts={
        "authority": {"NS": 2, "DS": 1, "RRSIG": 1},
        "additional": {"AAAA": 1, "RRSIG": 0}}
    )
    # complete delegation, complete glue
    test.run(bufsize=768, truncated=False, counts={
        "authority": {"NS": 2, "DS": 1, "RRSIG": 1},
        "additional": {"AAAA": 2, "RRSIG": 0}}
    )

# Unreachable delegation due to missing glue

with DelegationTest("unreachable.tc.test") as test:
    # incomplete delegation, no DS
    test.run(bufsize=512, truncated=True, counts={
        "authority": {"NS": 2, "DS": 0, "RRSIG": 0},
        "additional": {"AAAA": 0, "RRSIG": 0}}
    )
    # incomplete delegation, DS without signature
    test.run(bufsize=616, truncated=True, counts={
        "authority": {"NS": 2, "DS": 1, "RRSIG": 0},
        "additional": {"AAAA": 0, "RRSIG": 0}}
    )
    # complete delegation, no glue available
    test.run(bufsize=719, truncated=False, counts={
        "authority": {"NS": 2, "DS": 1, "RRSIG": 1},
        "additional": {"AAAA": 0, "RRSIG": 0}}
    )
# Delegation with foreign name servers

with DelegationTest("foreign.tc.test") as test:
    # incomplete delegation, no DS
    test.run(bufsize=512, truncated=True, counts={
        "authority": {"NS": 2, "DS": 0, "RRSIG": 0},
        "additional": {"AAAA": 0, "RRSIG": 0}}
    )
    # incomplete delegation, DS without signature
    test.run(bufsize=619, truncated=True, counts={
        "authority": {"NS": 2, "DS": 1, "RRSIG": 0},
        "additional": {"AAAA": 0, "RRSIG": 0}}
    )
    # complete delegation, no glue needed
    test.run(bufsize=722, truncated=False, counts={
        "authority": {"NS": 2, "DS": 1, "RRSIG": 1},
        "additional": {"AAAA": 0, "RRSIG": 0}}
    )

# Delegation with name servers from parent

with DelegationTest("parent.tc.test") as test:
    # incomplete delegation, no DS
    test.run(bufsize=512, truncated=True, counts={
        "authority": {"NS": 2, "DS": 0, "RRSIG": 0},
        "additional": {"AAAA": 0, "RRSIG": 0}}
    )
    # incomplete delegation, DS without signature
    test.run(bufsize=611, truncated=True, counts={
        "authority": {"NS": 2, "DS": 1, "RRSIG": 0},
        "additional": {"AAAA": 0, "RRSIG": 0}}
    )
    # complete delegation, no optional additionals
    test.run(bufsize=714, truncated=False, counts={
        "authority": {"NS": 2, "DS": 1, "RRSIG": 1},
        "additional": {"AAAA": 0, "RRSIG": 0}}
    )
    # complete delegation, one optional additional
    test.run(bufsize=742, truncated=False, counts={
        "authority": {"NS": 2, "DS": 1, "RRSIG": 1},
        "additional": {"AAAA": 1, "RRSIG": 0}}
    )
    # complete delegation, all optional additionals without signatures
    test.run(bufsize=770, truncated=False, counts={
        "authority": {"NS": 2, "DS": 1, "RRSIG": 1},
        "additional": {"AAAA": 2, "RRSIG": 0}}
    )
    # complete delegation, all optional additionals partially signed
    test.run(bufsize=873, truncated=False, counts={
        "authority": {"NS": 2, "DS": 1, "RRSIG": 1},
        "additional": {"AAAA": 2, "RRSIG": 1}}
    )
    # complete delegation, all optional additionals with signatures
    test.run(bufsize=976, truncated=False, counts={
        "authority": {"NS": 2, "DS": 1, "RRSIG": 1},
        "additional": {"AAAA": 2, "RRSIG": 2}}
    )

t.stop()
