#!/usr/bin/env python3

'''Unsigned -> signed(NSEC3) -> signed(NSEC) -> unsigned transitions.'''

def run(i):
    i.test.start()

    i.check()

    i.check(1)

    i.check(2)

    i.check(3)

