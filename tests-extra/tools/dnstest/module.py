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
    def _check_cmd(cls):
        if params.libtool_bin:
            prefix = [params.libtool_bin, "exec"]
        else:
            prefix = []

        return prefix + ["objdump", "-t", params.knot_bin]

    @classmethod
    def check(cls):
        '''Checks the server binary for the module code'''

        try:
            proc = Popen(cls._check_cmd(), stdout=PIPE, stderr=PIPE,
                         universal_newlines=True)
            (out, err) = proc.communicate()

            if re.search(cls.src_name, out):
                return

            raise Skip()
        except:
            raise Skip("Module '%s' not detected" % cls.conf_name)

    def get_conf_ref(self):
        return "%s/%s" % (self.conf_name, self.conf_id)

    def get_conf(self): pass

class ModSynthRecord(KnotModule):
    '''Automatic forward/reverse records module'''

    src_name = "synth_record_load"
    conf_name = "mod-synth-record"

    def __init__(self, mtype, prefix, ttl, network, origin=None):
        super().__init__()
        self.mtype = mtype
        self.prefix = prefix
        self.ttl = ttl
        self.network = network
        self.origin = origin

    def get_conf(self, conf=None):
        if not conf:
            conf = dnstest.config.KnotConf()

        conf.begin(self.conf_name)
        conf.id_item("id", self.conf_id)
        conf.item_str("type", self.mtype)
        if (self.prefix):
            conf.item_str("prefix", self.prefix)
        if (self.ttl):
            conf.item_str("ttl", self.ttl)
        conf.item_str("network", self.network)
        if (self.origin):
            conf.item_str("origin", self.origin)
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

class ModDnsproxy(KnotModule):
    '''Dnsproxy module'''

    src_name = "dnsproxy_load"
    conf_name = "mod-dnsproxy"

    def __init__(self, addr, port=53, catch_nxdomain=False):
        super().__init__()
        self.addr = addr
        self.port = port
        self.catch_nxdomain = catch_nxdomain

    def get_conf(self, conf=None):
        if not conf:
            conf = dnstest.config.KnotConf()

        conf.begin("remote")
        conf.id_item("id", "%s_%s" % (self.conf_name, self.conf_id))
        conf.item_str("address", "%s@%s" % (self.addr, self.port))
        conf.end()

        conf.begin(self.conf_name)
        conf.id_item("id", self.conf_id)
        conf.item_str("remote", "%s_%s" % (self.conf_name, self.conf_id))
        if (self.catch_nxdomain):
            conf.item_str("catch-nxdomain", "on")
        conf.end()

        return conf

class ModWhoami(KnotModule):
    '''Whoami module'''

    src_name = "whoami_load"
    conf_name = "mod-whoami"

    def __init__(self):
        super().__init__()

    def get_conf(self, conf=None):
        if not conf:
            conf = dnstest.config.KnotConf()

        conf.begin(self.conf_name)
        conf.id_item("id", self.conf_id)
        conf.end()

        return conf
