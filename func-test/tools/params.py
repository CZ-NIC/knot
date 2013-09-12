#!/usr/bin/env python3

'''
This module allows interchanging of running parameters between modules.
'''

# Common data directory (e.g. zone files).
common_data_dir = ""
# Current case relative directory.
test_dir = ""
# Current case absolute output directory.
out_dir = ""
# Current case log file.
case_log = None
# Current test object (for controling test from other modules).
test = None
# Indication for failed test.
err = False
