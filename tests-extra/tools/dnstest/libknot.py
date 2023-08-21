#!/usr/bin/env python3

import os
import sys

from dnstest.utils import Skip
import dnstest.params as params

try:
    sys.path.append(os.path.join(params.repo_binary("python"), "libknot"))
    import libknot
    import libknot.control
    import libknot.probe
    libknot.Knot(params.libknot_lib)
except:
    raise Skip("libknot not available or set KNOT_TEST_LIBKNOT to another libknot without ASAN")
