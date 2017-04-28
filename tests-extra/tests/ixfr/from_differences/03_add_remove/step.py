#!/usr/bin/env python3

'''Add and remove record/records.'''

def run(i):
    i.test.start()

    i.check()
    i.check_rec("rem1", "A", "1.2.3.4")
    i.check_rec("rem2", "AAAA", "::1")
    i.check_rec("rem2", "TXT", "some_text")
    i.check_rec("rem3", "AAAA", "::2")
    i.check_rec("rem4", "TXT", "some_text2")

    i.check(1)
    i.check_rec("rem1", "A", rcode="NXDOMAIN")
    i.check_rec("add1", "A", "1.2.3.4")

    i.check(2)
    i.check_rec("rem2", "AAAA", rcode="NXDOMAIN")
    i.check_rec("rem2", "TXT", rcode="NXDOMAIN")
    i.check_rec("add2", "AAAA", "::1")
    i.check_rec("add2", "TXT", "some_text")

    i.check(3)
    i.check_rec("rem3", "AAAA", rcode="NXDOMAIN")
    i.check_rec("rem4", "TXT", rcode="NXDOMAIN")
    i.check_rec("add3", "AAAA", "::2")
    i.check_rec("add4", "TXT", "some_text2")

    i.check(4)
    i.check_rec("rem4", "TXT", "some_text2")

