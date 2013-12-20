#!/usr/bin/env python3

'''DNS packet header parsing tests. '''

import shutil
from subprocess import check_call
from dnstest.test import Test
from dnstest.params import get_binary

# Find PROTOS binaries
protos_java_bin = get_binary("PROTOS_JAVA_BIN", "java")
protos_query_bin = get_binary("PROTOS_QUERY_BIN", "c09-dns-query-r1.jar")
protos_zonetransfer_bin = get_binary("PROTOS_ZONETRANSFER_BIN", "c09-dns-zonetransfer-r1.jar")
if not protos_java_bin:
    raise Exception("Java not found, skipping test.")

t = Test(ip = 4) # PROTOS works on IPv4
master = t.server("dummy")
slave = t.server("knot")
zone = t.zone("protos.invalid.", exists=False)
t.link(zone, master, slave)

# Update configuration
t.start()

''' Run PROTOS test case with given parameters. '''
def protos_run(name, binfile, params):
    if not binfile:
        return
    check_call([protos_java_bin, "-jar", binfile] + params,
               stdout=open(master.fout, mode="w"), stderr=open(master.ferr, mode="w"))
    shutil.move(master.fout, master.fout + "." + name)
    shutil.move(master.ferr, master.ferr + "." + name)

# Evaluate parameters
protos_params = ["--host", slave.addr, "--port", str(slave.port) ]
query_params = protos_params + ["--delay", "10", "--timeout", "100"]
zonetransfer_params = protos_params + [ "--delay", "10", "--sourceport", str(master.port) ]

# Run PROTOS (transfers)
protos_run('zonetransfer', protos_zonetransfer_bin, zonetransfer_params)

# Run PROTOS (queries)
protos_run('query', protos_query_bin, query_params)

t.end()
