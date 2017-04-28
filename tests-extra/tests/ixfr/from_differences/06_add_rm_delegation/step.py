#!/usr/bin/env python3

'''Add and remove zone delegation.'''

def run(i):
    i.test.start()

    i.check()
    i.check_rec("deleg", "NS", rcode="NXDOMAIN")
    i.check_rec("n.deleg", "A", rcode="NXDOMAIN")

    i.check(1)
    i.check_rec("deleg", "NS", rcode="NOERROR", nordata="n.deleg.example.com.")
    i.check_rec("n.deleg", "A", rcode="NOERROR", nordata="1.2.3.4")

    i.check(2)
    i.check_rec("deleg", "NS", rcode="NXDOMAIN")
    i.check_rec("n.deleg", "A", rcode="NXDOMAIN")

