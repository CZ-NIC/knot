#!/usr/bin/env python3

import os, sys, tempfile, time
import subprocess

def run_test(test_file, out_dir):
    return subprocess.call([test_file, out_dir])

test_cnt = 0
fail_cnt = 0
tests_dir = "./cases"
outs_dir = tempfile.mkdtemp(prefix="knottest-%s-" % int(time.time()))

print("Starting Knot test suite %s" % outs_dir)

for test in sorted(os.listdir(tests_dir)):
    test_dir = tests_dir + "/" + test
    if not os.path.isdir(test_dir):
        continue

    test_file = test_dir + "/test.py"
    if not os.path.isfile(test_file):
        print("Missing test file %s" % test_file)
        continue

    try:
        out_dir = outs_dir + "/" + test
        os.mkdir(out_dir)

        print("Test %s: " % test, end="")

        test_cnt = test_cnt + 1
        if run_test(test_file, out_dir):
            print("failed")
            fail_cnt = fail_cnt + 1
        else:
            print("ok")
    except (OSError, Exception) as err:
        print(format(err))
        exit(1)
    except:
        print("Unexpected error:", sys.exc_info()[0])

if fail_cnt:
    print("Failed tests: %i/%i" % (fail_cnt, test_cnt))
    exit(1)
else:
    print("All tests passed")
    exit(0)
