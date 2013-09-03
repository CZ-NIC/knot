#!/usr/bin/env python3

'''
This module allows interchanging of running parameters between modules.
All variables are set automatically.
'''

# Common data directory.
common_data_dir = ""
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
