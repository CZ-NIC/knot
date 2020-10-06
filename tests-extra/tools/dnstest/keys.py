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
from dnstest.context import Context

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
    def run(cls, conf_file, *args):
        cmdline = [dnstest.params.keymgr_bin]
        if conf_file:
            cmdline += ["-c", conf_file]
        cmdline += list(args)

        cmd = Popen(cmdline, stdout=PIPE, stderr=PIPE, universal_newlines=True)
        (stdout, stderr) = cmd.communicate()

        with open(Context().out_dir + "/keymgr.out", "a") as outf:
            outf.write(' '.join(cmdline))
            outf.write("\n" + stdout)
        with open(Context().out_dir + "/keymgr.err", "a") as errf:
            errf.write(stderr)

        return (cmd.returncode, stdout, stderr)

    @classmethod
    def run_check(cls, conf_file, *args):
        result = cls.run(conf_file, *args)
        exit_code, _, _ = result
        if exit_code != 0:
            raise Failed("Failed to run keymgr command %s." % list(args))
        else:
            return result

    @classmethod
    def run_fail(cls, conf_file, *args):
        result = cls.run(conf_file, *args)
        exit_code, _, _ = result
        if exit_code == 0:
            raise Failed("Keymgr passed when shall fail %s." % list(args))
        else:
            return result

class Key(object):
    '''DNSSEC key generator'''

    def __init__(self, confile, zone_name, ksk=False, zsk=None, alg="ECDSAP256SHA256",
                 key_len=-1, addtopolicy=None):
        self.confile = confile
        self.zone_name = zone_name
        self.alg = alg
        self.len = int(key_len)
        self.ksk = bool(ksk)
        if zsk is None:
            self.zsk = not self.ksk
        else:
            self.zsk = bool(zsk)
        self.addtopolicy = addtopolicy
        self.keyid = None

        if self.len < 0:
            try:
                self.len = int(alg[-3:])
            except ValueError:
                pass
            if self.len < 100 or self.len % 128 != 0:
                self.len = 256

    def _keymgr(self, *args):
        return Keymgr.run(self.confile, *args)

    def _gen_command(self):
        cmd = [
            self.zone_name, "generate",
            "ksk=" + str(self.ksk),
            "zsk=" + str(self.zsk),
            "algorithm=" + str(self.alg),
            "size=" + str(self.len)
        ]

        if self.addtopolicy is not None:
            cmd.append("addtopolicy=" + str(self.addtopolicy))

        return cmd

    def generate(self):
        command = self._gen_command()
        (exit_code, stdout, stderr) = self._keymgr(*command)
        if exit_code != 0:
            raise Failed("Can't generate key for zone '%s'. Stderr: %s" % (self.zone_name, stderr))
        self.keyid = stdout.strip()

    def change_role(self, ksk, zsk):
        self.ksk = bool(ksk)
        self.zsk = bool(zsk)
        command = [
            self.zone_name, "set", self.keyid, "ksk="+str(self.ksk), "zsk="+str(self.zsk)
        ]
        (exit_code, stdout, stderr) = self._keymgr(*command)
        if exit_code != 0:
            raise Failed("Can't change role of key for zone '%s'. Stderr: %s" % (self.zone_name, stderr))

