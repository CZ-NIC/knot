#!/usr/bin/env python3

'''Test for IXFR from differences and IXFR.'''

import os
import re
import importlib
import dnstest.test
from dnstest.utils import *
from dnstest.context import Context

class IxfrTopology():
    '''This class simplifies testing topology.'''

    def __init__(self, test, storage):
        '''
        zone diffs -> master(knot) -----> ref_slave(bind)
                                   -----> slave1(knot)
                   -> ref_master(bind) -> slave2(knot)
        '''

        self.test = test

        self.master = test.server("knot")
        self.slave1 = test.server("knot")
        self.slave2 = test.server("knot")
        self.ref_master = test.server("bind")
        self.ref_slave = test.server("bind")

        self.zone = test.zone("example.com.", storage=storage)

        self.test.link(self.zone, self.master, self.ref_slave, ixfr=True)
        self.test.link(self.zone, self.master, self.slave1, ixfr=True)
        self.test.link(self.zone, self.ref_master, self.slave2, ixfr=True)

        self.init_soa = None
        self.soa = None

    def clean(self):
        self.test.server_remove()

    def check(self, version=None):
        '''Check ixfr between all nodes.'''

        check_log("CHECK IXFR TOPOLOGY %s" % version)

        # Set zone file version if specified.
        if version:
            self.master.update_zonefile(self.zone, version)
            self.ref_master.update_zonefile(self.zone, version)
            self.master.reload()
            self.ref_master.reload()

        soa = self.ref_master.zone_wait(self.zone, self.soa)
        self.master.zone_wait(self.zone, serial=self.soa)
        self.ref_slave.zone_wait(self.zone, serial=self.soa)
        self.slave1.zone_wait(self.zone, serial=self.soa)
        self.slave2.zone_wait(self.zone, serial=self.soa)

        self.soa = soa

        if not self.init_soa:
            self.init_soa = soa

        serial = {self.zone[0].name: self.init_soa}
        self.test.xfr_diff(self.ref_master, self.master, self.zone, serial)
        self.test.xfr_diff(self.ref_master, self.ref_slave, self.zone, serial)
        self.test.xfr_diff(self.ref_master, self.slave1, self.zone, serial)
        self.test.xfr_diff(self.ref_master, self.slave2, self.zone, serial)

        check_log("====================================")

    def check_rec(self, rname, rtype, rdata=None, nordata=None,
                  rcode="NOERROR"):
        '''Ask all nodes for the given record.'''

        check_log("CHECK IXFR RECORD")

        # Transform relative owner.
        if rname[-1] != ".":
            rname += "." + self.zone[0].name

        check_log("%s:" % self.master.name)
        resp = self.master.dig(rname, rtype)
        resp.check(rdata=rdata, nordata=nordata, rcode=rcode)

        check_log("%s:" % self.slave1.name)
        resp = self.slave1.dig(rname, rtype)
        resp.check(rdata=rdata, nordata=nordata, rcode=rcode)

        check_log("%s:" % self.slave2.name)
        resp = self.slave2.dig(rname, rtype)
        resp.check(rdata=rdata, nordata=nordata, rcode=rcode)

        check_log("%s:" % self.ref_slave.name)
        resp = self.ref_slave.dig(rname, rtype)
        resp.check(rdata=rdata, nordata=nordata, rcode=rcode)

        check_log("====================================")

pattern = re.compile("^([0-9][0-9]_)")

t = dnstest.test.Test()

for dirname in sorted(os.listdir(Context().test_dir)):
    if pattern.match(dirname):
        mod_name = Context().module_name + "_" + dirname
        mod_path = os.path.join(Context().module_path, dirname, "step.py")
        spec = importlib.util.spec_from_file_location(mod_name, mod_path)
        mod = importlib.util.module_from_spec(spec)
        storage = os.path.join(Context().test_dir, dirname)

        i = IxfrTopology(t, storage)

        detail_log("####################################")
        check_log(">> %s <<" % mod_name)
        detail_log("zone_diffs -> master(%s) -----> ref_slave(%s)" %
                   (i.master.name, i.ref_slave.name))
        detail_log("                            -----> slave1(%s)" %
                   (i.slave1.name))
        detail_log("           -> ref_master(%s) -> slave2(%s)" %
                   (i.ref_master.name, i.slave2.name))
        detail_log("####################################")

        spec.loader.exec_module(mod)
        mod.run(i)
        i.clean()

t.end()
