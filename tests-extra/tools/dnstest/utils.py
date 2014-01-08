#!/usr/bin/env python3

import inspect
import os

import dnstest.params as params

SEP = "------------------------------------"

class Skip(Exception):
    """Exception for skipping current case."""
    pass

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

def check_log(text, stdout=False):
    '''Log message header'''

    msg = "%s (%s)" % (str(text), test_info())
    params.case_log.write(msg + "\n")
    if stdout and params.debug:
        print(msg)

def detail_log(text, stdout=False):
    '''Log message body'''

    msg = str(text)
    params.case_log.write(msg + "\n")
    if stdout and params.debug:
        print(msg)

def err(text):
    '''Log error'''

    check_log("ERROR", True)
    detail_log(text, True)
    detail_log(SEP, True)

def set_err(msg):
    '''Set error state'''

    params.err = True
    if not params.err_msg:
        params.err_msg = msg

def isset(value, name):
    '''Check if value is True'''

    if not value:
        set_err("IS SET " + name)
        check_log("IS SET " + name, True)
        detail_log("  False", True)
        detail_log(SEP, True)

def compare(value, expected, name):
    '''Compare two values'''

    if value != expected:
        set_err("COMPARE " + name)
        check_log("COMPARE " + name, True)
        detail_log("  (" + str(value) + ") != (" + str(expected) + ")", True)
        detail_log(SEP, True)

def compare_sections(section1, srv1name, section2, srv2name, name):
    '''Compare two message sections'''

    if section1 == section2:
        return

    set_err("COMPARE sections " + name)
    check_log("COMPARE %s SECTIONS" % name, True)

    for rrset in section1:
        if rrset not in section2:
            detail_log("%s has extra rrset:" % srv1name, True)
            detail_log("  %s" % rrset, True)

    for rrset in section2:
        if rrset not in section1:
            detail_log("%s has extra rrset:" % srv2name, True)
            detail_log("  %s" % rrset, True)

    detail_log(SEP, True)
