#!/usr/bin/env python3

import argparse, importlib, os, re, sys, tempfile, time, traceback
current_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(current_dir + "/tools")
from dnstest import log, err
import params

parser = argparse.ArgumentParser()
parser.add_argument("-d", dest="debug", action="store_true", \
                    help="enable exception traceback on stdout")
parser.add_argument("tests", metavar="[:]test[/case]", nargs="*", \
                    help="([exclude] | run) specific (test set | [test case])")
args = parser.parse_args()

params.common_data_dir = current_dir + "/tools/data/"
outs_dir = tempfile.mkdtemp(prefix="knottest-%s-" % int(time.time()))
tests_dir = "tests"
test_cnt = 0
fail_cnt = 0

excluded = dict()
included = dict()
for item in args.tests:
    if re.match(":", item):
        item = item[1:]
        storage = excluded
    else:
        storage = included

    parts = item.split("/")
    if len(parts) == 1:
        case = list()
    elif len(parts) == 2:
        case = [parts[1]]
    else:
        print("Invalid argument %s" % item)
        exit(1)
    test = parts[0]

    if test in storage:
        storage[test].append(case)
    else:
        storage[test] = case

# List all tests if nothing was specified.
if not included:
    for i in sorted(os.listdir("./" + tests_dir)):
        included[i] = list()

def save_traceback(outdir):
    file = open(params.out_dir + "/traceback", mode="a")
    traceback.print_exc(file=file)
    file.close()

log("Starting Knot test suite %s" % outs_dir)

for test in sorted(included):
    # Skip excluded test set.
    if test in excluded and not excluded[test]:
        continue

    # Check test directory.
    test_dir = "./%s/%s" % (tests_dir, test)
    if not os.path.isdir(test_dir):
        log("Invalid test name %s (ignored)" % test)
        continue

    log("Test \'%s\'" % test)

    # Set test cases to run.
    if not included[test]:
        # List all test cases.
        cases = sorted(os.listdir(test_dir))
    else:
        cases = included[test]

    for case in cases:
        # Skip excluded cases.
        if test in excluded and case in excluded[test]:
            continue

        test_cnt += 1

        case_dir = test_dir + "/" + case
        test_file = case_dir + "/test.py"
        if not os.path.isfile(test_file):
            log(" * case \'%s\': NOT EXECUTABLE!" % case)
            fail_cnt += 1
            continue

        log(" * case \'%s\'" % case)

        try:
            out_dir = outs_dir + "/" + test + "/" + case
            os.makedirs(out_dir, exist_ok=True)
            params.test_dir = case_dir
            params.out_dir = out_dir
            params.err = False
            params.errmsg = ""
        except OsError:
            fail_cnt += 1
            err("Can't create output directory %s" % out_dir)
            continue

        try:
            importlib.import_module("%s.%s.%s.test" % (tests_dir, test, case))
        except Exception as exc:
            params.err = True
            params.errmsg = format(exc)
            save_traceback(params.out_dir)
            if args.debug:
                traceback.print_exc()
        except BaseException as exc:
            log("Interrupted")
            save_traceback(params.out_dir)
            if args.debug:
                traceback.print_exc()
            exit(1)

        # Stop servers if still running.
        if params.err:
            fail_cnt += 1
            if params.errmsg:
                err(params.errmsg)

        if params.test:
            params.test.stop()

log("TEST CASES: %i, FAILED: %i" % (test_cnt, fail_cnt))

if fail_cnt:
    exit(1)
else:
    exit(0)

