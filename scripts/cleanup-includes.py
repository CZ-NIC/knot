#!/usr/bin/python -Es
# vim: et:sw=4:ts=4:sts=4
#
# Check #includes in source files and:
# - fix includes to be relative to src/
# - check if <config.h> is the first include in all .c sources
#

import os
import re
import sys

class SourceProcessor(object):
    def __init__(self):
        self._log_prefix = None

    def process(self, filename, code):
        raise NotImplemented()

    def log(self, message):
        print >>sys.stderr, "[%s] %s" % (self._log_prefix, message)

class FixIncludePaths(SourceProcessor):
    def __init__(self, src_root, search_paths):
        self._log_prefix = "include-paths"
        self._src_root = src_root
        self._search_paths = search_paths

    def _fix_include(self, filename, include):
        current_path = os.path.split(filename)[0]
        for search_path in [current_path] + self._search_paths:
            new_include = os.path.join(search_path, include)
            if os.path.exists(new_include):
                new_include = os.path.relpath(new_include, self._src_root)
                return new_include
        return include

    def process(self, filename, code):
        def callback(match):
            (prefix, path, suffix) = match.groups()
            fixed_path = self._fix_include(filename, path)
            return "%s%s%s" % (prefix, fixed_path, suffix)

        fixed_code = re.sub(r'(#\s*include\s+")([^"]+)(")', callback, code)
        if code != fixed_code:
            self.log("fixed %s" % filename)

        return fixed_code

class TestConfigH(SourceProcessor):
    def __init__(self):
        self._log_prefix = "config.h"

    def _check_code(self, code):
        first_include = re.search('#\s*include\s+(".+"|<.+>)', code)
        return first_include is not None and first_include.group(1) == "<config.h>"

    def process(self, filename, code):
        if not re.search(r'\.h$', filename) and not self._check_code(code):
            self.log("config.h is not first include in %s" % filename)
        return code

# ----------------------------------------------------------------------------

from subprocess import Popen, PIPE

def run(command):
    p = Popen(command, stdout=PIPE, stderr=PIPE)
    (out, errout) = p.communicate()
    if p.returncode != 0:
        raise Exception("Command %s failed.", command)
    return out

# ----------------------------------------------------------------------------

git_root = run(["git", "rev-parse", "--show-toplevel"]).strip()
os.chdir(git_root)

command = ["git", "ls-files", "src/*.h", "src/*.c", "src/*.y"]
filenames = run(command).splitlines()

pipeline = [
    FixIncludePaths("src", ["src", "src/libknot"]),
    TestConfigH(),
]

for filename in filenames:
    code = open(filename, "r").read()
    modified = False

    for processor in pipeline:
        new_code = processor.process(filename, code)
        if new_code != code:
            modified = True
            code = new_code

    if modified:
        open(filename, "w").write(code)
