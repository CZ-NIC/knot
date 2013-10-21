#!/usr/bin/env python3

import argparse, importlib, logging, os, re, sys, tempfile, time, traceback
current_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(current_dir + "/tools")
import params

# Parse command line arguments.
parser = argparse.ArgumentParser()
parser.add_argument("-d", dest="debug", action="store_true", \
                    help="enable exception traceback on stdout")
parser.add_argument("tests", metavar="[:]test[/case]", nargs="*", \
                    help="([exclude] | run) specific (test set | [test case])")
args = parser.parse_args()

params.debug = True if args.debug else False
params.common_data_dir = current_dir + "/tools/data/"
tests_dir = "tests"

# Process tests/cases arguments.
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
    file = open(params.out_dir + "/traceback.log", mode="a")
    traceback.print_exc(file=file)
    file.close()

def create_log(logger, filename="", level=logging.NOTSET):
    if filename:
        handler = logging.FileHandler(filename)
    else:
        handler = logging.StreamHandler()
    handler.setLevel(level)
    formatter = logging.Formatter('%(asctime)s# %(message)s', "%H:%M:%S")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return handler

timestamp = int(time.time())
today = time.strftime("%Y-%m-%d", time.localtime(timestamp))
outs_dir = tempfile.mkdtemp(prefix="knottest-%s-" % timestamp)

# Set up logging.
log = logging.getLogger()
log.setLevel(logging.NOTSET)
create_log(log)
create_log(log, outs_dir + "/summary.log", logging.NOTSET)

log.info("KNOT TESTING SUITE %s" % today)
log.info("Working directory %s" % outs_dir)

case_cnt = 0
fail_cnt = 0
for test in sorted(included):
    # Skip excluded test set.
    if test in excluded and not excluded[test]:
        continue

    # Check test directory.
    test_dir = "%s/%s/%s" % (current_dir, tests_dir, test)
    if not os.path.isdir(test_dir):
        log.error("Test \'%s\':\tIGNORED (invalid folder)" % test)
        continue

    log.info("Test \'%s\'" % test)

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

        case_cnt += 1

        case_dir = test_dir + "/" + case
        test_file = case_dir + "/test.py"
        if not os.path.isfile(test_file):
            log.error(" * case \'%s\':\tMISSING" % case)
            fail_cnt += 1
            continue

        try:
            out_dir = outs_dir + "/" + test + "/" + case
            os.makedirs(out_dir, exist_ok=True)
            params.test_dir = case_dir
            params.out_dir = out_dir
            params.case_log = open(out_dir + "/case.log", mode="a")
            params.test = None
            params.err = False
            params.err_msg = ""
        except OsError:
            fail_cnt += 1
            log.error(" * case \'%s\':\tEXCEPTION (no dir \'%s\')" %
                      (case, out_dir))
            continue

        try:
            importlib.import_module("%s.%s.%s.test" % (tests_dir, test, case))
        except Exception as exc:
            params.err = True
            save_traceback(params.out_dir)
            if args.debug:
                traceback.print_exc()
            else:
                log.error(" * case \'%s\':\tEXCEPTION (%s)" %
                          (case, format(exc)))
        except BaseException as exc:
            save_traceback(params.out_dir)
            if args.debug:
                traceback.print_exc()
            else:
                log.info("INTERRUPTED")
            # Stop servers if still running.
            if params.test:
                params.test.end()
            exit(1)
        else:
            if params.err:
                msg = " (%s)" % params.err_msg if params.err_msg else ""
                log.info(" * case \'%s\':\tFAILED%s" % (case, msg))
                fail_cnt += 1
            else:
                log.info(" * case \'%s\':\tOK" % case)

        # Stop servers if still running.
        if params.test:
            params.test.end()

        params.case_log.close()

if fail_cnt:
    log.info("TEST CASES: %i, FAILED: %i" % (case_cnt, fail_cnt))
    exit(1)
else:
    log.info("TEST CASES: %i, SUCCESS" % (case_cnt))
    exit(0)

