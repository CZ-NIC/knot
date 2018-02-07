#!/usr/bin/env python3

import argparse
import datetime
import importlib
import logging
import os
import re
import sys
import tempfile
import time
import traceback

current_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(current_dir, "tools"))
import dnstest.params as params
import dnstest.utils

TESTS_DIR = "tests"

def save_traceback(outdir):
    path = os.path.join(params.out_dir, "traceback.log")
    with open(path, mode="a") as f:
        traceback.print_exc(file=f)

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

def log_environment(filename):
    def want_log(key):
        return key in [ "CC", "CPP", "CFLAGS", "CPPFLAGS",
                        "LDFLAGS", "LIBS",
                        "PKG_CONFIG", "PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR",
                        "YAAC", "YFLAGS",
                        "MALLOC_PERTURB_", "MALLOC_CHECK_" ] or \
              re.match(r'.+_(CFLAGS|LIBS)$', key) or \
              re.match(r'^KNOT_TEST_', key)

    with open(filename, "w") as log:
        lines = ["%s=%s\n" % (k, v) for (k, v) in os.environ.items() if want_log(k)]
        log.writelines(lines)

def parse_args(cmd_args):
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", dest="debug", action="store_true", \
                        help="enable exception traceback on stdout")
    parser.add_argument("-n", dest="repeat", action="store", \
                        help="repeat the test n times")
    parser.add_argument("tests", metavar="[:]test[/case]", nargs="*", \
                        help="([exclude] | run) specific (test set | [test case])")
    args = parser.parse_args(cmd_args)

    params.debug = True if args.debug else False
    params.repeat = int(args.repeat) if args.repeat else 1
    params.common_data_dir = os.path.join(current_dir, "data")

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
            sys.exit(1)
        test = parts[0]

        if test in storage:
            storage[test].extend(case)
        else:
            storage[test] = case

    # List all tests if nothing was specified.
    if not included:
        tests_path = os.path.join(current_dir, TESTS_DIR)
        for i in sorted(os.listdir(tests_path)):
            included[i] = list()

    return included, excluded

def log_failed(log_dir, msg, indent=True):
    fname = os.path.join(log_dir, "failed.log")
    first = False if os.path.isfile(fname) else True

    file = open(fname, mode="a")
    if first:
        print("Failed tests:", file=file)
    print("%s%s" % ("  " if indent else "", msg), file=file)
    file.close()

def main(args):
    included, excluded = parse_args(args)

    timestamp = int(time.time())
    today = time.strftime("%Y-%m-%d", time.localtime(timestamp))
    outs_dir = tempfile.mkdtemp(prefix="knottest-%s-" % timestamp,
                                dir=params.outs_dir)

    # Try to create symlink to the latest result.
    last_link = os.path.join(params.outs_dir, "knottest-last")
    try:
        if os.path.exists(last_link):
            os.remove(last_link)
        os.symlink(outs_dir, last_link)
    except:
        pass

    # Write down environment
    log_environment(os.path.join(outs_dir, "environment.log"))

    # Set up logging.
    log = logging.getLogger()
    log.setLevel(logging.NOTSET)
    create_log(log)
    create_log(log, os.path.join(outs_dir, "summary.log"), logging.NOTSET)

    log.info("KNOT TESTING SUITE %s" % today)
    log.info("Working directory %s" % outs_dir)

    ref_time = datetime.datetime.now().replace(microsecond=0)

    case_cnt = 0
    fail_cnt = 0
    skip_cnt = 0
    for test in sorted(included):
        # Skip excluded test set.
        if test in excluded and not excluded[test]:
            continue

        # Check test directory.
        test_dir = os.path.join(current_dir, TESTS_DIR, test)
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
          loaded_module = None
          for repeat in range(params.repeat):
            # Skip excluded cases.
            if test in excluded and case in excluded[test]:
                continue

            case_n = case if params.repeat == 1 else case + str(repeat)

            case_str_err = (" * case \'%s\':" % case).ljust(33)
            case_str_fail = ("%s/%s" % (test, case)).ljust(30)
            case_cnt += 1

            case_dir = os.path.join(test_dir, case)
            test_file = os.path.join(case_dir, "test.py")
            if not os.path.isfile(test_file):
                log.error(case_str_err + "MISSING")
                skip_cnt += 1
                continue

            try:
                out_dir = os.path.join(outs_dir, test, case_n)
                log_file = os.path.join(out_dir, "case.log")

                os.makedirs(out_dir, exist_ok=True)
                params.module = "%s.%s.%s" % (TESTS_DIR, test, case)
                params.test_dir = case_dir
                params.out_dir = out_dir
                params.case_log = open(log_file, mode="a")
                params.test = None
                params.err = False
                params.err_msg = ""
            except OsError:
                msg = "EXCEPTION (no dir \'%s\')" % out_dir
                log.error(case_str_err + msg)
                log_failed(outs_dir, case_str_fail + msg)
                fail_cnt += 1
                continue

            try:
                if loaded_module:
                    importlib.reload(loaded_module)
                else:
                    loaded_module = importlib.import_module("%s.%s.%s.test" % (TESTS_DIR, test, case))
            except dnstest.utils.Skip as exc:
                log.error(case_str_err + "SKIPPED (%s)" % format(exc))
                skip_cnt += 1
            except dnstest.utils.Failed as exc:
                save_traceback(params.out_dir)

                desc = format(exc)
                msg = "FAILED (%s)" % (desc if desc else exc.__class__.__name__)
                if params.err and params.err_msg:
                    msg += " AND (" + params.err_msg + ")"
                log.error(case_str_err + msg)
                log_failed(outs_dir, case_str_fail + msg)

                if params.debug:
                    traceback.print_exc()

                fail_cnt += 1
            except Exception as exc:
                save_traceback(params.out_dir)

                desc = format(exc)
                msg = "EXCEPTION (%s)" % (desc if desc else exc.__class__.__name__)
                log.error(case_str_err + msg)
                log_failed(outs_dir, case_str_fail + msg)

                if params.debug:
                    traceback.print_exc()

                fail_cnt += 1
            except BaseException as exc:
                save_traceback(params.out_dir)
                if params.debug:
                    traceback.print_exc()
                else:
                    log.info("INTERRUPTED")
                # Stop servers if still running.
                if params.test:
                    params.test.end()
                sys.exit(1)
            else:
                if params.err:
                    msg = "FAILED" + \
                          ((" (" + params.err_msg + ")") if params.err_msg else "")
                    log.info(case_str_err + msg)
                    log_failed(outs_dir, case_str_fail + msg)
                    fail_cnt += 1
                else:
                    log.info(case_str_err + "OK")

            # Stop servers if still running.
            if params.test:
                params.test.end()

            params.case_log.close()

    time_diff = datetime.datetime.now().replace(microsecond=0) - ref_time
    msg_time = "TOTAL TIME: %s, " % time_diff
    msg_cases = "TEST CASES: %i" % case_cnt
    msg_skips = ", SKIPPED: %i" % skip_cnt if skip_cnt > 0 else ""
    msg_res = ", FAILED: %i" % fail_cnt if fail_cnt > 0 else ", SUCCESS"
    log.info(msg_time + msg_cases + msg_skips + msg_res)

    if fail_cnt:
        log_failed(outs_dir, "Total %i/%i" % (fail_cnt, case_cnt), indent=False)
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main(sys.argv[1:])
