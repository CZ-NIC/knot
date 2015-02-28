#!/usr/bin/env python3

import re
from subprocess import Popen, PIPE, check_call, CalledProcessError
from dnstest.utils import *
import dnstest.config
import dnstest.params as params
import dnstest.server

class KnotModule(object):
    '''Query module configuration'''

    # Instance counter.
    count = 1
    # Module callback name in the source.
    src_name = None
    # Module name in the configuration.
    conf_name = None

    def __init__(self):
        self.conf_id = "id%s" % type(self).count
        type(self).count += 1

    @classmethod
    def check(self):
        '''Checks the server binary for the module code'''

        try:
            proc = Popen(["objdump", "-t", params.knot_bin],
                         stdout=PIPE, stderr=PIPE, universal_newlines=True)
            (out, err) = proc.communicate()

            if re.search(self.src_name, out):
                return

            raise Skip()
        except:
            raise Skip("Module '%s' not detected" % self.conf_name)

    def get_conf_ref(self):
        return "%s/%s" % (self.conf_name, self.conf_id)

    def get_conf(self): pass

class ModSynthRecord(KnotModule):
    '''Automatic forward/reverse records module'''

    src_name = "synth_record_load"
    conf_name = "mod-synth-record"

    def __init__(self, mtype, prefix, ttl, address, zone=None):
        super().__init__()
        self.mtype = mtype
        self.prefix = prefix
        self.ttl = ttl
        self.address = address
        self.zone = zone

    def get_conf(self, conf=None):
        if not conf:
            conf = dnstest.config.KnotConf()

        conf.begin(self.conf_name)
        conf.id_item("id", self.conf_id)
        conf.item_str("type", self.mtype)
        conf.item_str("prefix", self.prefix)
        conf.item_str("ttl", self.ttl)
        conf.item_str("address", self.address)
        if (self.zone):
            conf.item_str("zone", self.zone)
        conf.end()

        return conf

class ModDnstap(KnotModule):
    '''Dnstap module'''

    src_name = "dnstap_load"
    conf_name = "mod-dnstap"

    def __init__(self, sink):
        super().__init__()
        self.sink = sink

    def get_conf(self, conf=None):
        if not conf:
            conf = dnstest.config.KnotConf()

        conf.begin(self.conf_name)
        conf.id_item("id", self.conf_id)
        conf.item_str("sink", self.sink)
        conf.end()

        return conf
