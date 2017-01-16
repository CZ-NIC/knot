#!/usr/bin/python -Es
# vim: et:ts=4:sw=4:colorcolumn=100
#
# Configuration for You Complete Me (YCM) code-completion engine for Vim.
#
# This file is released into the public domain.
#

import sys
import os

DIR = os.path.dirname(__file__)

FLAGS = [
    '-std=gnu99',
    '-Wall', '-Wno-unused', '-Werror=implicit', '-Wno-#warnings',
    '-DCONFIG_DIR=', '-DRUN_DIR=', '-DSTORAGE_DIR=', '-DPACKAGE_VERSION=',
]

CONFIG_H = 'src/config.h'

INCLUDES = [
    ('src/dnssec/shared', ['src/dnssec/lib', 'src/dnssec/lib/dnssec']),
    ('src/dnssec/lib', ['src/dnssec/shared', 'src/dnssec/lib/dnssec']),
    ('src/dnssec/tests', ['src/dnssec/shared', 'src/dnssec/lib', 'src/dnssec/lib/dnssec', 'libtap']),
    ('src/utils/keymgr', ['src/dnssec', 'src/dnssec/lib', 'src']),
    ('src/utils/knsec3hash', ['src/dnssec', 'src/dnssec/lib', 'src']),
    ('src', ['src/dnssec/lib']),
    ('tests', ['src', 'src/dnssec/lib', 'libtap']),
]

def relative_path(filename):
    return os.path.relpath(filename, DIR)

def absolute_path(filename):
    return os.path.normpath(os.path.join(DIR, filename))

def includes_for(filename):
    relative = relative_path(filename)
    for prefix, includes in INCLUDES:
        if relative.startswith(prefix + '/'):
            return [prefix] + includes
    return []

def include_flag(path):
    return "-I%s" % absolute_path(path)

def FlagsForFile(filename):
    # input filename is an absolute path
    config = ["-include", absolute_path(CONFIG_H)]
    includes = [include_flag(f) for f in includes_for(filename)]
    return {'flags': FLAGS + config + includes, 'do_cache': True}

if __name__ == '__main__':
    print >>sys.stderr, "Not runnable."
    sys.exit(1)
