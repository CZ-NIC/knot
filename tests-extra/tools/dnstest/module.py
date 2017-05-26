#!/usr/bin/env python3

import os
import re
from subprocess import Popen, PIPE, check_call
from dnstest.utils import *
import dnstest.config
import dnstest.params as params

class KnotModule(object):
    '''Query module configuration'''

    MOD_CONF_PREFIX = "mod-"
    MOD_API_PREFIX = "knotd_mod_api_"

    # Instance counter.
    count = 1
    # Module API name suffix.
    mod_name = None
    # Empty configuration
    empty = False

    def __init__(self):
        self.conf_id = "id%s" % type(self).count
        type(self).count += 1

    @property
    def conf_name(self):
        return self.MOD_CONF_PREFIX + self.mod_name

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

            if re.search(cls.MOD_API_PREFIX + cls.mod_name, out):
                return

            raise Skip()
        except:
            raise Skip("Module '%s' not detected" % cls.mod_name)

    def get_conf_ref(self):
        if self.empty:
            return str(self.conf_name)
        else:
            return "%s/%s" % (self.conf_name, self.conf_id)

    def get_conf(self, conf=None): pass

class ModSynthRecord(KnotModule):
    '''Automatic forward/reverse records module'''

    mod_name = "synthrecord"

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

    mod_name = "dnstap"

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

class ModRRL(KnotModule):
    '''RRL module'''

    mod_name = "rrl"

    def __init__(self, rate_limit, slip=None, table_size=None, whitelist=None):
        super().__init__()
        self.rate_limit = rate_limit
        self.slip = slip
        self.table_size = table_size
        self.whitelist = whitelist

    def get_conf(self, conf=None):
        if not conf:
            conf = dnstest.config.KnotConf()

        conf.begin(self.conf_name)
        conf.id_item("id", self.conf_id)
        conf.item_str("rate-limit", self.rate_limit)
        if self.slip or self.slip == 0:
            conf.item_str("slip", self.slip)
        if self.table_size:
            conf.item_str("table-size", self.table_size)
        if self.whitelist:
            conf.item_str("whitelist", self.whitelist)
        conf.end()

        return conf

class ModDnsproxy(KnotModule):
    '''Dnsproxy module'''

    mod_name = "dnsproxy"

    def __init__(self, addr, port=53, nxdomain=False, fallback=True):
        super().__init__()
        self.addr = addr
        self.port = port
        self.fallback = fallback
        self.nxdomain = nxdomain

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
        conf.item_str("fallback", "on" if self.fallback else "off")
        conf.item_str("catch-nxdomain", "on" if self.nxdomain else "off")
        conf.end()

        return conf

class ModWhoami(KnotModule):
    '''Whoami module'''

    mod_name = "whoami"
    empty = True

    def __init__(self):
        super().__init__()

class ModOnlineSign(KnotModule):
    '''Online-sign module'''

    mod_name = "onlinesign"

    def __init__(self, algorithm=None, key_size=None):
        super().__init__()
        self.algorithm = algorithm
        self.key_size = key_size
        if not algorithm:
            self.empty = True

    def get_conf(self, conf=None):
        if not conf:
            conf = dnstest.config.KnotConf()

        if self.algorithm:
            conf.begin("policy")
            conf.id_item("id", "%s_%s" % (self.conf_name, self.conf_id))
            conf.item_str("algorithm", self.algorithm)
            if self.key_size:
                conf.item_str("zsk-size", self.key_size)
            conf.end()

            conf.begin(self.conf_name)
            conf.id_item("id", self.conf_id)
            conf.item_str("policy", "%s_%s" % (self.conf_name, self.conf_id))
            conf.end()

        return conf

class ModRosedb(KnotModule):
    '''Rosedb module'''

    mod_name = "rosedb"

    def __init__(self, dbdir):
        super().__init__()
        self.dbdir = dbdir

    def get_conf(self, conf=None):
        if not conf:
            conf = dnstest.config.KnotConf()

        conf.begin(self.conf_name)
        conf.id_item("id", self.conf_id)
        conf.item_str("dbdir", "%s" % (self.dbdir))
        conf.end()

        return conf

    def add_record(self, owner, rtype, ttl, rdata, code="-", target="-"):
        prepare_dir(self.dbdir)
        try:
            check_call([params.rosedb_tool, self.dbdir, 'add', owner, rtype,
                        ttl, rdata, code, target],
                       stdout=open(os.path.join(params.out_dir, "rosedb-tool.out"), mode="a"),
                       stderr=open(os.path.join(params.out_dir, "rosedb-tool.err"), mode="a"))
        except:
            set_err("ROSEDB_TOOL")
            detail_log("!Failed to add a record into rosedb '%s'" % self.dbdir)
            detail_log(SEP)

class ModStats(KnotModule):
    '''Stats module'''

    mod_name = "stats"

    def __init__(self):
        super().__init__()

    def _bool(self, conf, name, value=True):
        conf.item_str(name, "on" if value else "off")

    def get_conf(self, conf=None):
        if not conf:
            conf = dnstest.config.KnotConf()

        conf.begin(self.conf_name)
        conf.id_item("id", self.conf_id)
        self._bool(conf, "request-protocol", True)
        self._bool(conf, "server-operation", True)
        self._bool(conf, "request-bytes", True)
        self._bool(conf, "response-bytes", True)
        self._bool(conf, "edns-presence", True)
        self._bool(conf, "flag-presence", True)
        self._bool(conf, "response-code", True)
        self._bool(conf, "reply-nodata", True)
        self._bool(conf, "query-type", True)
        self._bool(conf, "query-size", True)
        self._bool(conf, "reply-size", True)
        conf.end()

        return conf
