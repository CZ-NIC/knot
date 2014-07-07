#!/usr/bin/env python3

import argparse, importlib, logging, os, re, sys, tempfile, time, traceback
current_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(current_dir + "/tools")
import dnstest.params as params
import dnstest.utils

TESTS_DIR = "tests"
COMMON_DATA_DIR = "data"
LAST_WORKING_DIR = params.outs_dir + "/knottest-last"

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

def parse_args(cmd_args):
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", dest="debug", action="store_true", \
                        help="enable exception traceback on stdout")
    parser.add_argument("tests", metavar="[:]test[/case]", nargs="*", \
                        help="([exclude] | run) specific (test set | [test case])")
    args = parser.parse_args(cmd_args)

    params.debug = True if args.debug else False
    params.common_data_dir = current_dir + '/' + COMMON_DATA_DIR

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
        for i in sorted(os.listdir("./" + TESTS_DIR)):
            included[i] = list()

    return included, excluded

def log_failed(log_dir, msg, indent=True):
    fname = log_dir + "/failed.log"
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
    try:
        if os.path.exists(LAST_WORKING_DIR):
            os.remove(LAST_WORKING_DIR)
        os.symlink(outs_dir, LAST_WORKING_DIR)
    except:
        pass

    # Set up logging.
    log = logging.getLogger()
    log.setLevel(logging.NOTSET)
    create_log(log)
    create_log(log, outs_dir + "/summary.log", logging.NOTSET)

    log.info("KNOT TESTING SUITE %s" % today)
    log.info("Working directory %s" % outs_dir)

    case_cnt = 0
    fail_cnt = 0
    skip_cnt = 0
    for test in sorted(included):
        # Skip excluded test set.
        if test in excluded and not excluded[test]:
            continue

        # Check test directory.
        test_dir = "%s/%s/%s" % (current_dir, TESTS_DIR, test)
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

            case_str_err = (" * case \'%s\':" % case).ljust(31)
            case_str_fail = ("%s/%s" % (test, case)).ljust(28)
            case_cnt += 1

            case_dir = test_dir + "/" + case
            test_file = case_dir + "/test.py"
            if not os.path.isfile(test_file):
                log.error(case_str_err + "MISSING")
                skip_cnt += 1
                continue

            try:
                out_dir = outs_dir + "/" + test + "/" + case
                os.makedirs(out_dir, exist_ok=True)
                params.module = TESTS_DIR + "." + test + "." + case
                params.test_dir = case_dir
                params.out_dir = out_dir
                params.case_log = open(out_dir + "/case.log", mode="a")
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
                importlib.import_module("%s.%s.%s.test" % (TESTS_DIR, test, case))
            except dnstest.utils.Skip as exc:
                log.error(case_str_err + "SKIPPED (%s)" % format(exc))
                skip_cnt += 1
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
                          (("(" + params.err_msg + ")") if params.err_msg else "")
                    log.info(case_str_err + msg)
                    log_failed(outs_dir, case_str_fail + msg)
                    fail_cnt += 1
                else:
                    log.info(case_str_err + "OK")

            # Stop servers if still running.
            if params.test:
                params.test.end()

            params.case_log.close()

    msg_cases = "TEST CASES: %i" % case_cnt
    msg_skips = ", SKIPPED: %i" % skip_cnt if skip_cnt > 0 else ""
    msg_res = ", FAILED: %i" % fail_cnt if fail_cnt > 0 else ", SUCCESS"
    log.info(msg_cases + msg_skips + msg_res)

    if fail_cnt:
        log_failed(outs_dir, "Total %i/%i" % (fail_cnt, case_cnt), indent=False)
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main(sys.argv[1:])
