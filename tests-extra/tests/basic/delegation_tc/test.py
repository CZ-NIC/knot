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
    def __init__(self, name, authoritative=False):
        self._name = name
        self._auth = authoritative

    def _get_flags(self, truncated):
        if self._auth:
            return ("AA TC", "") if truncated else ("AA", "TC")
        else:
            return ("TC", "AA") if truncated else ("", "AA TC")

    def run(self, bufsize=None, truncated=False, counts=None):
        name = "%s%s" % ("" if self._auth else "www.", self._name)
        rtype = "NS" if self._auth else "A"
        flags, noflags = self._get_flags(truncated)
        resp = knot.dig(name, rtype, udp=True, dnssec=True, bufsize=bufsize)
        resp.check(rcode="NOERROR", noflags=noflags, flags=flags)
        for section in counts:
            for rtype in counts[section]:
                resp.check_count(counts[section][rtype], rtype, section)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_vaue, traceback):
        return False

# Authoritative answer with glue of foreign name server

with DelegationTest("tc.test", authoritative=True) as test:
    # incomplete answer, no signature
    test.run(bufsize=592, truncated=True, counts={
        "answer": {"NS": 4, "RRSIG": 0},
        "additional": {"AAAA": 0, "RRSIG": 0}}
    )
    # complete answer, no additionals
    test.run(bufsize=695, truncated=False, counts={
        "answer": {"NS": 4, "RRSIG": 1},
        "additional": {"AAAA": 0, "RRSIG": 0}}
    )
    # complete answer, one optional additional for foreign name server
    test.run(bufsize=723, truncated=False, counts={
        "answer": {"NS": 4, "RRSIG": 1},
        "additional": {"AAAA": 1, "RRSIG": 0}}
    )
    # complete answer, all optional additionals
    test.run(bufsize=751, truncated=False, counts={
        "answer": {"NS": 4, "RRSIG": 1},
        "additional": {"AAAA": 2, "RRSIG": 0}}
    )
    # complete answer, all optional additionals with signature
    test.run(bufsize=2000, truncated=False, counts={
        "answer": {"NS": 4, "RRSIG": 1},
        "additional": {"AAAA": 2, "RRSIG": 1}}
    )

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
    test.run(bufsize=2000, truncated=False, counts={
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
    test.run(bufsize=2000, truncated=False, counts={
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
    test.run(bufsize=2000, truncated=False, counts={
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
    test.run(bufsize=2000, truncated=False, counts={
        "authority": {"NS": 2, "DS": 1, "RRSIG": 1},
        "additional": {"AAAA": 2, "RRSIG": 2}}
    )

# Delegation with mixed set of servers

with DelegationTest("mixed.tc.test") as test:
    # incomplete delegation, no DS
    test.run(bufsize=512, truncated=True, counts={
        "authority": {"NS": 6, "DS": 0, "RRSIG": 0},
        "additional": {"AAAA": 0, "RRSIG": 0}}
    )
    # incomplete delegation, DS without signature
    test.run(bufsize=709, truncated=True, counts={
        "authority": {"NS": 6, "DS": 1, "RRSIG": 0},
        "additional": {"AAAA": 0, "RRSIG": 0}}
    )
    # complete delegation, no glue
    test.run(bufsize=812, truncated=True, counts={
        "authority": {"NS": 6, "DS": 1, "RRSIG": 1},
        "additional": {"AAAA": 0, "RRSIG": 0}}
    )
    # complete delegation, partial glue
    test.run(bufsize=840, truncated=True, counts={
        "authority": {"NS": 6, "DS": 1, "RRSIG": 1},
        "additional": {"AAAA": 1, "RRSIG": 0}}
    )
    # complete delegation, full glue, no optional
    test.run(bufsize=868, truncated=False, counts={
        "authority": {"NS": 6, "DS": 1, "RRSIG": 1},
        "additional": {"AAAA": 2, "RRSIG": 0}}
    )
    # complete delegation, full glue, optional without signature
    test.run(bufsize=896, truncated=False, counts={
        "authority": {"NS": 6, "DS": 1, "RRSIG": 1},
        "additional": {"AAAA": 3, "RRSIG": 0}}
    )
    # complete delegation, full glue, optional
    test.run(bufsize=924, truncated=False, counts={
        "authority": {"NS": 6, "DS": 1, "RRSIG": 1},
        "additional": {"AAAA": 4, "RRSIG": 0}}
    )
    # complete delegation, full glue, optional with signature
    test.run(bufsize=2000, truncated=False, counts={
        "authority": {"NS": 6, "DS": 1, "RRSIG": 1},
        "additional": {"AAAA": 4, "RRSIG": 1}}
    )

t.stop()
