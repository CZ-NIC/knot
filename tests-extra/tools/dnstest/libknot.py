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
except Exception as e:
    raise Skip("libknot error (%s)" % str(e))
