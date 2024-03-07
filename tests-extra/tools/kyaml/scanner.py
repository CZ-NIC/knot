#!/usr/bin/env python3

from yaml.scanner import Scanner

class KnotScanner(Scanner):

    def __init__(self):
        Scanner.__init__(self)

    # Public methods.

    def check_value(self):
        # IPv6
        if self.peek(1) == ':':
            return False
        return super().check_value()

    def check_plain(self):
        # IPv6 is also plain text
        if self.peek() == ':' and self.peek(1) == ':':
            return True
        return super().check_plain()
