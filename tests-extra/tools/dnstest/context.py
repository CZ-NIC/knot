#!/usr/bin/env python3

class Context(object):
    class _Context(object):
        def __init__(self):
            # Current module name.
            self.module = ""
            # Current case relative directory.
            self.test_dir = ""
            # Current case absolute output directory.
            self.out_dir = ""
            # Current case log file.
            self.case_log = None
            # Current test object (for stopping it from the main script).
            self.test = None

            # Indication for failed test.
            self.err = False
            # What is wrong.
            self.err_msg = ""

    _INSTANCE = None

    def __new__(cls):
        if not Context._INSTANCE:
            Context._INSTANCE = Context._Context()
        return Context._INSTANCE
    def __getattribute__(self, name):
        return getattr(self._INSTANCE, name)
    def __setattr__(self, name, val):
        return setattr(self._INSTANCE, name, val)
