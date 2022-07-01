#!/usr/bin/env python3

import argparse
import datetime
import importlib
import importlib.util
import logging
import multiprocessing
import os
import re
import sys
import tempfile
import time
import traceback

current_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(current_dir, "tools"))
from dnstest.context import Context
import dnstest.params as params
import dnstest.utils

TESTS_DIR = "tests"

log = None
outs_dir = None

def save_traceback(outdir, exc):
    path = os.path.join(Context().out_dir, "traceback.log")
    with open(path, mode="a") as f:
        tb = traceback.TracebackException.from_exception(exc, capture_locals=True)
        print("".join(tb.format()), file=f)

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
                        "MALLOC_PERTURB_", "MALLOC_CHECK_" ] or \
              re.match(r'.+_(CFLAGS|LIBS)$', key) or \
              re.match(r'^KNOT_TEST_', key)

    with open(filename, "w") as log:
        lines = ["export %s=\"%s\"\n" % (k, v) for (k, v) in os.environ.items() if want_log(k)]
        log.writelines(lines)

def parse_args(cmd_args):
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", dest="debug", action="store_true", \
                        help="enable exception traceback on stdout")
    parser.add_argument("-n", "--repeat", dest="repeat", action="store", \
                        default=1, type=int, help="run test set n times, endless when 0")
    parser.add_argument("-j", "--jobs", dest="jobs", action="store", type=int,\
                        help="number of concurrent jobs")
    parser.add_argument("-e", "--exit-on-error", dest="error_exit", \
                        action="store_true", help="stop execution on error")
    parser.add_argument("tests", metavar="[:]test[/case]", nargs="*", \
                        help="([exclude] | run) specific (test set | [test case])")
    args = parser.parse_args(cmd_args)

    params.debug = True if args.debug else False
    params.repeat = max(int(args.repeat), 0)
    params.jobs = max(int(args.jobs), 1) if args.jobs else 1
    params.common_data_dir = os.path.join(current_dir, "data")
    params.exit_on_error = args.error_exit

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
                cases = sorted(os.listdir(os.path.join(current_dir, TESTS_DIR, parts[0])))
            except:
                print("Failed to access test '%s'" % item)
                sys.exit(1)
        elif len(parts) == 2:
            cases = [parts[1]]
        else:
            print("Invalid argument '%s'" % item)
            sys.exit(1)
        test = parts[0]

        if test in storage:
            storage[test].extend(cases)
        else:
            storage[test] = cases

    # List all tests if nothing was specified.
    if not included:
        tests_path = os.path.join(current_dir, TESTS_DIR)
        for test in sorted(os.listdir(tests_path)):
            try:
                included[test] = sorted(os.listdir(os.path.join(tests_path, test)))
            except:
                print("Failed to access tests in '%s'" % tests_path)
                sys.exit(1)

    # Filter out excluded tests.
    for test, cases in excluded.items():
        if cases:
            if test in included:
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

def job(tasks, results, stop):
    case_cnt = 0
    fail_cnt = 0
    skip_cnt = 0

    ctx = Context()

    while True:
        if tasks.empty() or (params.exit_on_error and stop.value):
            break
        test, case, repeat = tasks.get()
        if params.repeat == 0:
            tasks.put((test, case, repeat + 1))

        test_dir = os.path.join(current_dir, TESTS_DIR, test)
        case_n = case if params.repeat == 1 else case + " #" + str(repeat)
        case_str_err = (" * %s/%s" % (test, case_n)).ljust(35)
        case_str_fail = ("%s/%s" % (test, case_n)).ljust(32)
        case_cnt += 1

        case_dir = os.path.join(test_dir, case)
        test_file = os.path.join(case_dir, "test.py")
        if not os.path.isfile(test_file):
            log.error(case_str_err + "MISSING")
            skip_cnt += 1
            continue

        try:
            out_dir = os.path.join(outs_dir, test, case_n.replace(" ", ""))
            log_file = os.path.join(out_dir, "case.log")

            os.makedirs(out_dir, exist_ok=True)
            ctx.module_name = "%s_%s_%i" % (test, case, repeat)
            ctx.module_path = os.path.join(os.path.dirname(sys.argv[0]), TESTS_DIR, test, case)
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
            stop.value = True
            continue

        try:
            module_entry = os.path.join(ctx.module_path, "test.py")
            spec = importlib.util.spec_from_file_location(ctx.module_name, module_entry)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        except dnstest.utils.Skip as exc:
            log.error(case_str_err + "SKIPPED (%s)" % format(exc))
            skip_cnt += 1
        except dnstest.utils.Failed as exc:
            save_traceback(ctx.out_dir, exc)

            desc = format(exc)
            msg = "FAILED (%s)" % (desc if desc else exc.__class__.__name__)
            if ctx.err and ctx.err_msg:
                msg += " AND (" + ctx.err_msg + ")"
            log.error(case_str_err + msg)
            log_failed(outs_dir, case_str_fail + msg)

            if params.debug:
                traceback.print_exc()

            fail_cnt += 1
            stop.value = True
        except Exception as exc:
            save_traceback(ctx.out_dir, exc)

            desc = format(exc)
            msg = "EXCEPTION (%s)" % (desc if desc else exc.__class__.__name__)
            log.error(case_str_err + msg)
            log_failed(outs_dir, case_str_fail + msg)

            if params.debug:
                traceback.print_exc()

            fail_cnt += 1
            stop.value = True
        except BaseException as exc:
            save_traceback(ctx.out_dir, exc)
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
                stop.value = True
            else:
                log.info(case_str_err + "OK")

        # Stop servers if still running.
        if ctx.test:
            ctx.test.end()

        ctx.case_log.close()
    results.put((case_cnt, fail_cnt, skip_cnt))

def main(args):
    global log
    global outs_dir

    tasks = multiprocessing.Queue()
    results = multiprocessing.SimpleQueue()
    stop = multiprocessing.Value('i', False)

    case_cnt = 0
    fail_cnt = 0
    skip_cnt = 0

    included = parse_args(args)

    range_end = 2 if params.repeat == 0 else params.repeat + 1
    for n in range(1, range_end):
        for test, cases in included.items():
            for case in cases:
                tasks.put((test, case, n), block=False)

    timestamp = int(time.time())
    today = time.strftime("%Y-%m-%d", time.localtime(timestamp))
    outs_dir = tempfile.mkdtemp(prefix="knottest-%s-" % timestamp,
                                dir=params.outs_dir)
    os.chmod(outs_dir, 0o755)

    # Try to create symlink to the latest result.
    last_link = os.path.join(params.home_dir, "knottest-last")
    try:
        if os.path.lexists(last_link):
            os.remove(last_link)
        os.symlink(outs_dir, last_link)
    except:
        pass

    # Make the symlink in the test directory too.
    # (For backward compatibility?)
    if os.path.realpath(params.outs_dir) != "/tmp":
        outs_dir_relative = os.path.basename(outs_dir)
        last_link_relative = os.path.join(params.outs_dir,"knottest-last")
        try:
            os.symlink(outs_dir_relative, last_link_relative)
        except:
            pass

    # Write down environment.
    log_environment(os.path.join(outs_dir, "environment.log"))

    # Set up logging.
    log = logging.getLogger()
    log.setLevel(logging.NOTSET)
    create_log(log)
    create_log(log, os.path.join(outs_dir, "summary.log"), logging.NOTSET)

    log.info("KNOT TESTING SUITE %s" % today)
    log.info("Working directory %s" % outs_dir)

    ref_time = datetime.datetime.now().replace(microsecond=0)

    if params.jobs > 1: # Multi-thread run
        threads = []
        for _ in range(params.jobs):
            t = multiprocessing.Process(target=job, args=(tasks, results, stop))
            threads.append(t)
            t.start()

        for thread in threads:
            thread.join()
    else: # Single-thread run
        job(tasks, results, stop)

    while not results.empty():
        a, b, c = results.get()
        case_cnt += a
        fail_cnt += b
        skip_cnt += c

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
