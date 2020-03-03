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
import threading

current_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(current_dir, "tools"))
import dnstest.params as params
import dnstest.utils
from dnstest.thread_context import ThreadContext

TESTS_DIR = "tests"
case_cnt = 0
fail_cnt = 0
skip_cnt = 0
included = None
included_list = []
lock = None
log = None
outs_dir = None

def save_traceback(outdir):
    path = os.path.join(ThreadContext().out_dir, "traceback.log")
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
    parser.add_argument("-j", "--jobs", dest="jobs", action="store", type=int,\
                        help="number of concurrent jobs")
    parser.add_argument("tests", metavar="[:]test[/case]", nargs="*", \
                        help="([exclude] | run) specific (test set | [test case])")
    args = parser.parse_args(cmd_args)

    params.debug = True if args.debug else False
    params.repeat = int(args.repeat) if args.repeat else 1
    params.jobs = max(int(args.jobs), 1) if args.jobs else 1
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
            try:
                case = sorted(os.listdir(os.path.join(current_dir, TESTS_DIR, parts[0])))
            except FileNotFoundError:
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
        for test in sorted(os.listdir(tests_path)):
            try:
                included[test] = sorted(os.listdir(os.path.join(tests_path, test)))
            except FileNotFoundError:
                included[test] = list()

    for test, cases in excluded.items():
        if cases:
            if included[test]:
                for case in cases:
                    included[test].remove(case)
        else:
            del included[test]

    return included

def log_failed(log_dir, msg, indent=True):
    fname = os.path.join(log_dir, "failed.log")
    first = False if os.path.isfile(fname) else True

    file = open(fname, mode="a")
    if first:
        print("Failed tests:", file=file)
    print("%s%s" % ("  " if indent else "", msg), file=file)
    file.close()

def job():
    global case_cnt
    global fail_cnt
    global skip_cnt
    global included_list
    global lock

    ctx = ThreadContext()
    loaded_module = None
    loaded_module_name = None
    loaded_module_run = False

    while included_list:
        lock.acquire()
        test, case, repeat = included_list.pop(0)
        lock.release()

        # Check test directory.
        test_dir = os.path.join(current_dir, TESTS_DIR, test)
        if not os.path.isdir(test_dir):
            log.error("Test \'%s\':\tIGNORED (invalid folder)" % test)
            continue
        
        case_n = case if params.repeat == 1 else case + "#" + str(repeat)

        case_str_err = (" * case \'%s/%s\':" % (test, case_n)).ljust(41)
        case_str_fail = ("%s/%s" % (test, case_n)).ljust(30)
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
            ctx.module = "%s.%s.%s" % (TESTS_DIR, test, case)
            ctx.test_dir = case_dir
            ctx.out_dir = out_dir
            ctx.case_log = open(log_file, mode="a")
            ctx.test = None
            ctx.err = False
            ctx.err_msg = ""
        except OsError:
            msg = "EXCEPTION (no dir \'%s\')" % out_dir
            log.error(case_str_err + msg)
            log_failed(outs_dir, case_str_fail + msg)
            fail_cnt += 1
            continue

        try:
            loaded_module_name = "%s.%s.%s.test" % (TESTS_DIR, test, case)
            if loaded_module_name in sys.modules.keys():
                loaded_module = sys.modules[loaded_module_name]
            else:
                loaded_module = importlib.import_module(loaded_module_name)
            try:
                loaded_module.run_test()
            except AttributeError:
                raise dnstest.utils.Skip("Missing testcase entry point!")
        except dnstest.utils.Skip as exc:
            log.error(case_str_err + "SKIPPED (%s)" % format(exc))
            skip_cnt += 1
        except dnstest.utils.Failed as exc:
            save_traceback(ctx.out_dir)

            desc = format(exc)
            msg = "FAILED (%s)" % (desc if desc else exc.__class__.__name__)
            if ctx.err and ctx.err_msg:
                msg += " AND (" + ctx.err_msg + ")"
            log.error(case_str_err + msg)
            log_failed(outs_dir, case_str_fail + msg)

            if params.debug:
                traceback.print_exc()

            fail_cnt += 1
        except Exception as exc:
            save_traceback(ctx.out_dir)

            desc = format(exc)
            msg = "EXCEPTION (%s)" % (desc if desc else exc.__class__.__name__)
            log.error(case_str_err + msg)
            log_failed(outs_dir, case_str_fail + msg)

            if params.debug:
                traceback.print_exc()

            fail_cnt += 1
        except BaseException as exc:
            save_traceback(ctx.out_dir)
            if params.debug:
                traceback.print_exc()
            else:
                log.info("INTERRUPTED")
                # Stop servers if still running.
            if ctx.test:
                ctx.test.end()
            sys.exit(1)
        else:
            if ctx.err:
                msg = "FAILED" + \
                      ((" (" + ctx.err_msg + ")") if ctx.err_msg else "")
                log.info(case_str_err + msg)
                log_failed(outs_dir, case_str_fail + msg)
                fail_cnt += 1
            else:
                log.info(case_str_err + "OK")

        # Stop servers if still running.
        if ctx.test:
            ctx.test.end()

        ctx.case_log.close()


def main(args):
    global included
    global log
    global outs_dir
    global included_list
    global lock

    included = parse_args(args)
    for n in range(1, params.repeat + 1):
        for test, cases in included.items():
            for case in cases:
                included_list.append((test, case, n))

    lock = threading.Lock()

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

    if params.jobs > 1: # Parallel run
        threads = []
        for _ in range(params.jobs):
            t = threading.Thread(target=job, daemon=True)
            threads.append(t)
            t.start()

        for thread in threads:
            thread.join()
    else: # Single threaded run
        job()


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
