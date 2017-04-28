#!/usr/bin/env python3

'''Add record/records.'''

def run(i):
    i.test.start()

    i.check()
    i.check_rec("add1", "A", rcode="NXDOMAIN")
    i.check_rec("add2", "AAAA", rcode="NXDOMAIN")
    i.check_rec("add2", "TXT", rcode="NXDOMAIN")
    i.check_rec("add3", "AAAA", rcode="NXDOMAIN")
    i.check_rec("add3", "A", rcode="NXDOMAIN")
    i.check_rec("add4", "TXT", rcode="NXDOMAIN")

    i.check(1)
    i.check_rec("add1", "A", "1.2.3.4")

    i.check(2)
    i.check_rec("add2", "AAAA", "::1")
    i.check_rec("add2", "TXT", "some_text")

    i.check(3)
    i.check_rec("add3", "AAAA", "::2")
    i.check_rec("add4", "TXT", "some_text2")

    i.check(4)
    i.check_rec("add3", "AAAA", "::2")
    i.check_rec("add3", "A", "1.1.1.1")
    i.check_rec("add4", "TXT", "some_text2")
    i.check_rec("add4", "TXT", "some_text3")

