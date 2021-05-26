#!/usr/bin/env python3

import sys

from dnstest.utils import Skip
import dnstest.params as params

try:
    sys.path.append(params.repo_binary("python"))
    import libknot
    import libknot.control
    import libknot.probe
    libknot.Knot(params.libknot_lib)
except:
    raise Skip("libknot not available or set KNOT_TEST_LIBKNOT to another libknot without ASAN")
