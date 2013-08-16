#!/usr/bin/env python3

'''
This module allows interchanging of running parameters between modules.
All variables are set automatically.
'''

# Current case relative directory.
test_dir = ""
# Current case absolute output directory.
out_dir = ""
# Current test object (for controling test from other modules).
test = None
# Test result.
err = False
# Error message text.
errmsg = ""
# Enable exception traceback.
debug = False
