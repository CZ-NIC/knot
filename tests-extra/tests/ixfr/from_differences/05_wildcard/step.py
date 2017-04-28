#!/usr/bin/env python3

'''Add wildcard records.'''

def run(i):
    i.test.start()

    i.check()
    i.check_rec("a.wild", "AAAA", "::2")
    i.check_rec("b.wild", "A", "1.1.1.1")
    i.check_rec("b.wild", "AAAA", nordata="::3")
    i.check_rec("*.wild", "ANY", rcode="NXDOMAIN")
    i.check_rec("*.wc", "ANY", rcode="NXDOMAIN")

    i.check(1)
    i.check_rec("a.wild", "AAAA", "::2")
    i.check_rec("b.wild", "A", "1.1.1.1")
    i.check_rec("b.wild", "AAAA", nordata="::3")
    i.check_rec("c.wild", "AAAA", "::3")
    i.check_rec("*.wild", "AAAA", "::3")

    i.check(2)
    i.check_rec("a.wc", "A", "2.2.2.2")
    i.check_rec("b.wc", "A", "2.2.2.2")
    i.check_rec("b.wc", "AAAA", nordata="::4")
    i.check_rec("*.wc", "A", "2.2.2.2")

    i.check(3)
    i.check_rec("a.wc", "A", "3.3.3.3")
    i.check_rec("b.wc", "A", nordata="2.2.2.2")
    i.check_rec("b.wc", "AAAA", "::4")
    i.check_rec("c.wc", "A", "2.2.2.2")
    i.check_rec("*.wc", "A", "2.2.2.2")

