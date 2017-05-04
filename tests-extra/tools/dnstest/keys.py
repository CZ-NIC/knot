#!/usr/bin/env python3

import base64
import os
import random
import string
import dns.tsigkeyring
from subprocess import DEVNULL, PIPE, Popen

import dnstest.server
import dnstest.params
from dnstest.utils import *

class Tsig(object):
    '''TSIG key generator'''

    algs = {
        "hmac-md5":    16,
        "hmac-sha1":   20,
        "hmac-sha224": 28,
        "hmac-sha256": 32,
        "hmac-sha384": 48,
        "hmac-sha512": 64
    }

    vocabulary = string.ascii_uppercase + string.ascii_lowercase + \
                 string.digits

    def __init__(self, name=None, alg=None, key=None):
        if not name:
            nlabels = random.randint(1, 10)

            self.name = ""
            for i in range(nlabels):
                label_len = random.randint(1, 63)

                # Check for maximal dname length (255 B = max fqdn in wire).
                # 255 = 1 leading byte + 253 + 1 trailing byte.
                if len(self.name) + 1 + label_len > 253:
                    break

                # Add label separator.
                if i > 0:
                    self.name += "."

                self.name += "".join(random.choice(Tsig.vocabulary)
                             for x in range(label_len))
        else:
            self.name = str(name)

        if not alg:
            self.alg = random.choice(list(Tsig.algs.keys()))
        else:
            if alg not in Tsig.algs:
                raise Failed("Unsupported TSIG algorithm %s" % alg)
            self.alg = alg

        if not key:
            self.key = base64.b64encode(os.urandom(Tsig.algs[self.alg])). \
                       decode('ascii')
        else:
            self.key = str(key)

        # TSIG preparation for pythondns utils.
        if self.alg == "hmac-md5":
            _alg = "hmac-md5.sig-alg.reg.int"
        else:
            _alg = self.alg

        _key = dns.tsigkeyring.from_text({
            self.name: self.key
        })
        self.key_params = dict(keyname=self.name, keyalgorithm=_alg, keyring=_key)

    def dump(self, filename):
        s = dnstest.config.BindConf()

        s.begin("key", self.name)
        s.item("algorithm", self.alg)
        s.item_str("secret", self.key)
        s.end()

        file = open(filename, mode="w")
        file.write(s.conf)
        file.close()

class Keymgr(object):
    @classmethod
    def run(cls, kasp_dir, *args):
        cmdline = [dnstest.params.keymgr_bin]
        if kasp_dir:
            cmdline += ["-d", kasp_dir]
        cmdline += list(args)

        cmd = Popen(cmdline, stdout=PIPE, stderr=PIPE, universal_newlines=True)
        (stdout, stderr) = cmd.communicate()
        return (cmd.returncode, stdout, stderr)

    @classmethod
    def run_check(cls, kasp_dir, *args):
        result = cls.run(kasp_dir, *args)
        exit_code, _, _ = result
        if exit_code != 0:
            raise Failed("Failed to run keymgr command %s." % list(args))
        else:
            return result

class Key(object):
    '''DNSSEC key generator'''

    def __init__(self, key_dir, zone_name, ksk=False, alg="rsasha256", key_len=512):
        self.dir = key_dir
        self.zone_name = zone_name
        self.alg = alg
        self.len = key_len
        self.ksk = ksk

    def _keymgr(self, *args):
        return Keymgr.run(self.dir, *args)

    def _gen_command(self):
        cmd = [
            self.zone_name, "generate",
            "ksk=" + str(self.ksk),
            "algorithm=" + str(self.alg),
            "size=" + str(self.len)
        ]

        return cmd

    def generate(self):
        command = self._gen_command()
        (exit_code, _, _) = self._keymgr(*command)
        if exit_code != 0:
            raise Failed("Can't generate key for zone '%s'." % self.zone_name)
