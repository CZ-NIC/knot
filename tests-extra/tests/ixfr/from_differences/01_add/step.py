#!/usr/bin/env python3

'''Add record/records to zone file.'''

def run(i):
    i.test.start()

    i.check()

    i.check(1)
    i.check_rec("add1", "A", "1.2.3.4")

    i.check(2)
    i.check_rec("add2", "AAAA", "::1")
    i.check_rec("add2", "TXT", "some text")

    i.test.end()
