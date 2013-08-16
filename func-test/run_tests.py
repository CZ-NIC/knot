#!/usr/bin/env python3

import importlib, os, sys, tempfile, time
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/tools")
from dnstest import log, err
import params

outs_dir = tempfile.mkdtemp(prefix="knottest-%s-" % int(time.time()))
tests_dir = "tests"
test_cnt = 0
fail_cnt = 0

log("Starting Knot test suite %s" % outs_dir)

for test in sorted(os.listdir("./" + tests_dir)):
    test_dir = "./%s/%s" % (tests_dir, test)
    if not os.path.isdir(test_dir):
        continue

    log("Test \'%s\'" % test)

    for case in sorted(os.listdir(test_dir)):
        case_dir = test_dir + "/" + case
        test_file = case_dir + "/test.py"
        if not os.path.isfile(test_file):
            continue

        log(" * case \'%s\'" % case)
        test_cnt += 1

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
        except KeyboardInterrupt:
            log("Interrupted by user")
            exit(1)
        except:
            params.err = True
            params.errmsg = sys.exc_info()[0]

        if params.err:
            fail_cnt += 1
            if params.errmsg:
                err(params.errmsg)

        # Stop servers if still running.
        if params.test:
            params.test.stop()

if fail_cnt:
    log("Failed test cases: %i/%i" % (fail_cnt, test_cnt))
    exit(1)
else:
    log("All test cases passed")
    exit(0)
