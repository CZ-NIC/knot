#!/usr/bin/env python3

import sys

from dnstest.utils import Skip
import dnstest.params as params

try:
    sys.path.append(params.repo_binary("python"))
    import libknot.control
    libknot.control.load_lib(params.libknot_lib)
except:
    raise Skip("libknot not available or set KNOT_TEST_LIBKNOT to another libknot without ASAN")
