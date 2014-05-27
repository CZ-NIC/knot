#!/usr/bin/env python3

'''
This module allows interchanging of running parameters between modules.
'''

import os, shutil

def get_binary(env_name, default):
    env = os.environ.get(env_name)
    # Disable.
    if env == "":
        return ""
    # Use new or default value.
    name = env if env else default
    path = shutil.which(name)
    # Notify user that he set wrong binary
    if env and not path:
        print("Binary \'%s\' not found" % name)
        exit(1)
    return path

def get_param(env_name, default):
    env = os.environ.get(env_name)
    # Disable.
    if env == "":
        return ""
    # Use new or default value.
    return env if env else default

# Indication of debug mode (print ERR on stdout).
debug = False

# KNOT_TEST_VALGRIND - valgrind binary if defined.
valgrind_bin = get_binary("KNOT_TEST_VALGRIND", "valgrind")
# KNOT_TEST_VALGRIND_FLAGS - valgrind flags.
valgrind_flags = get_param("KNOT_TEST_VALGRIND_FLAGS",
                           "--leak-check=full --vgdb=yes")
# KNOT_TEST_GDB - gdb binary.
gdb_bin = get_binary("KNOT_TEST_GDB", "gdb")
# KNOT_TEST_VGDB - vgdb binary.
vgdb_bin = get_binary("KNOT_TEST_VGDB", "vgdb")
# KNOT_TEST_KNOT - Knot binary.
knot_bin = get_binary("KNOT_TEST_KNOT", "../src/knotd")
# KNOT_TEST_KNOTC - Knot control binary.
knot_ctl = get_binary("KNOT_TEST_KNOTC", "../src/knotc")
# KNOT_TEST_BIND - Bind binary.
bind_bin = get_binary("KNOT_TEST_BIND", "named")
# KNOT_TEST_BINDC - Bind control binary.
bind_ctl = get_binary("KNOT_TEST_BINDC", "rndc")
# KNOT_TEST_NSD - Nsd binary.
#nsd_bin = get_binary("KNOT_TEST_NSD", "nsd")
# KNOT_TEST_NSDC - Nsd control binary.
#nsd_ctl = get_binary("KNOT_TEST_NSDC", "nsdc")

# KNOT_TEST_OUTS_DIR - working directories location.
outs_dir = get_param("KNOT_TEST_OUTS_DIR", "/tmp")

# Common data directory (e.g. zone files).
common_data_dir = ""

# Current module name.
module = ""
# Current case relative directory.
test_dir = ""
# Current case absolute output directory.
out_dir = ""
# Current case log file.
case_log = None
# Current test object (for stopping it from the main script).
test = None

# Indication for failed test.
err = False
# What is wrong.
err_msg = ""
