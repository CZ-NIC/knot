#!/usr/bin/env python3

'''Remove record/records.'''

def run(i):
    i.test.start()

    i.check()
    i.check_rec("dns1", "A", "192.0.2.1")
    i.check_rec("dns1", "A", "1.1.1.1")
    i.check_rec("dns2", "A", "192.0.2.2")
    i.check_rec("dns2", "AAAA", "2001:db8::2")
    i.check_rec("rem1", "A", "1.2.3.4")
    i.check_rec("rem2", "AAAA", "::1")
    i.check_rec("rem2", "TXT", "some_text")
    i.check_rec("rem3", "AAAA", "::2")
    i.check_rec("rem4", "TXT", "some_text2")

    i.check(1)
    i.check_rec("rem1", "A", rcode="NXDOMAIN")

    i.check(2)
    i.check_rec("rem2", "AAAA", rcode="NXDOMAIN")
    i.check_rec("rem2", "TXT", rcode="NXDOMAIN")

    i.check(3)
    i.check_rec("rem3", "AAAA", rcode="NXDOMAIN")
    i.check_rec("rem4", "TXT", rcode="NXDOMAIN")

    i.check(4)
    i.check_rec("dns1", "A", "192.0.2.1")
    i.check_rec("dns1", "A", nordata="1.1.1.1")
    i.check_rec("dns2", "A", "192.0.2.2")
    i.check_rec("dns2", "AAAA", nordata="2001:db8::2")

