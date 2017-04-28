#!/usr/bin/env python3

'''Unsigned -> signed(NSEC) -> signed(NSEC3) -> unsigned transitions.'''

def run(i):
    i.test.start()

    i.check()

    i.check(1)

    i.check(2)

    i.check(3)

