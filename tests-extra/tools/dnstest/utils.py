#!/usr/bin/env python3

import inspect
import os
import time

import dnstest.params as params

SEP = "------------------------------------"

class Skip(Exception):
    """Exception for skipping current case."""
    pass

def prepare_dir(path):
    try:
        os.makedirs(path)
    except OSError:
        if not os.path.isdir(path):
            raise Exception("Can't create directory '%s'" % path)

def test_info():
    '''Get current test case name'''

    info = ""
    frames = inspect.getouterframes(inspect.currentframe())
    for frame in frames:
        if params.test_dir == os.path.dirname(frame[1]):
            info = "%s#%i" % (params.test_dir, frame[2])
            break
    parts = info.split("/")

    if len(parts) > 1:
        return parts[-2] + "/" + parts[-1]
    else:
        return "dnstest"

def check_log(text):
    '''Log message header'''

    msg = "(%s) %s (%s)\n" % (time.strftime("%H:%M:%S"), str(text), test_info())
    params.case_log.write(msg)
    params.case_log.flush()

def detail_log(text):
    '''Log message body'''

    msg = "%s\n" % text
    params.case_log.write(msg)
    params.case_log.flush()

def set_err(msg):
    '''Set error state'''

    params.err = True
    if not params.err_msg:
        params.err_msg = msg

def isset(value, name):
    '''Check if value is True'''

    if not value:
        set_err("IS SET \'%s\'" % name)
        check_log("ERROR: IS SET \'%s\'" % name)
        detail_log(SEP)
        return True
    return False

def compare(value, expected, name):
    '''Compare two values'''

    if value != expected:
        set_err("COMPARE \'%s\'" % name)
        check_log("ERROR: COMPARE \'%s\'" % name)
        detail_log("  (%s) != (%s)" % (value, expected))
        detail_log(SEP)
        return True
    return False

def compare_sections(section1, srv1name, section2, srv2name, name):
    '''Compare two message sections'''

    different = False

    for rrset in section1:
        if rrset not in section2:
            if not different:
                different = True
                set_err("COMPARE SECTION %s" % name)
                check_log("ERROR: COMPARE SECTION %s" % name)
            detail_log("!Extra rrset %s:" % srv1name)
            detail_log("  %s" % rrset)

    for rrset in section2:
        if rrset not in section1:
            if not different:
                different = True
                set_err("COMPARE SECTION %s" % name)
                check_log("ERROR: COMPARE SECTION %s" % name)
            detail_log("!Extra rrset %s:" % srv2name)
            detail_log("  %s" % rrset)

    if different:
        detail_log(SEP)
