#!/usr/bin/env python3

'''Change record/records.'''

def run(i):
    i.test.start()

    i.check()
    i.check_rec("ch1", "A", "1.2.3.4")
    i.check_rec("ch2", "AAAA", "::1")
    i.check_rec("ch2", "TXT", "some_text")
    i.check_rec("ch3", "MX", "10 ch1.example.com.")
    i.check_rec("ch3", "MX", "20 ch2.example.com.")

    i.check(1)
    i.check_rec("ch1", "A", nordata="1.2.3.4")
    i.check_rec("ch1", "A", "1.1.1.1")

    i.check(2)
    i.check_rec("ch2", "AAAA", "::1")
    i.check_rec("ch2", "TXT", nordata="some_text")
    i.check_rec("ch2", "TXT", "some_better_text")

    i.check(3)
    i.check_rec("ch3", "MX", nordata="10 ch1.example.com.")
    i.check_rec("ch3", "MX", "10 mail.example.com.")
    i.check_rec("ch3", "MX", nordata="20 ch2.example.com.")
    i.check_rec("ch3", "MX", "40 ch2.example.com.")

