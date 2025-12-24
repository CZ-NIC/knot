#!/usr/bin/env python3

import os
import shutil
import textwrap
from subprocess import Popen, check_output
from dnstest.context import Context
from dnstest.utils import *

class Keystore(object):
    def __init__(self, id: str, ksk_only: bool = None, key_label: bool = None):
        self.id = id
        self.ksk_only = ksk_only
        self.key_label = key_label

class KeystorePEM(Keystore):
    def __init__(self, id: str, ksk_only: bool = None, key_label: bool = None):
        super().__init__(id, ksk_only, key_label)

    def config(self):
        return os.path.join(Context().test.out_dir, f"{self.backend()}-{self.id}")

    def backend(self):
        return "pem"

    def env(self):
        return { }

    def clear(self):
        shutil.rmtree(self.config())

    def has_key(self, id: str):
        return os.path.isfile(os.path.join(self.config(), f"{id}.pem"))

class KeystoreSoftHSM(Keystore):
    so_pin = "12345"

    def __init__(self, id: str, ksk_only: bool = None, key_label: bool = None,
                 token: str = None, passwd: str = None, so_path: str = None):
        super().__init__(id, ksk_only, key_label)
        self.so_path = so_path if so_path else "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
        self.passwd = passwd if passwd else "1234"
        self.token = token if token else "knot"
        self.dir = os.path.join(Context().test.out_dir, f"{self.backend()}-{self.id}")
        self.init()

    def config(self):
        return f"pkcs11:token={self.token};pin-value={self.passwd} {self.so_path}"

    def backend(self):
        return "pkcs11"

    def config_file(self):
        return os.path.join(self.dir, "softhsm.conf")

    def env(self):
        return { "SOFTHSM2_CONF": self.config_file() }

    def clear(self):
        shutil.rmtree(os.path.join(self.dir, "tokens"))

    def has_key(self, id: str):
        urls = check_output(['p11tool', '--list-token-urls'],
                           env=dict(os.environ, **self.env())).decode('ascii')
        url = ssearch(urls, r'(pkcs11:.*SoftHSM.*)')
        keys = check_output(['p11tool', '--login', '--set-pin', self.passwd, '--list-keys', url],
                           env=dict(os.environ, **self.env())).decode('ascii')
        id_sep = ':'.join(textwrap.wrap(id, 2))
        key = ssearch(keys, r'(ID:.*%s.*)' % id_sep)
        return False if not key else len(key) > 0

    def init(self, keystore=None):
        if not os.path.isdir(self.dir):
            os.makedirs(os.path.join(self.dir, "tokens"))
            with open(self.config_file(), "w") as conf_file:
                config = (
                    f"directories.tokendir = {self.dir}/tokens/\n"
                     "objectstore.backend = file\n"
                     "log.level = INFO\n"
                )
                conf_file.write(config)

        if keystore:
            self.clear()
            shutil.copytree(os.path.join(keystore.dir, "tokens"), os.path.join(self.dir, "tokens"))
        else:
            init_process = Popen(
                ['softhsm2-util', '--init-token', '--free', f'--label={self.token}',
                 f'--pin={self.passwd}', f'--so-pin={self.so_pin}', f'--module={self.so_path}'],
                    stdout=open(os.path.join(self.dir, "stdout"), mode='a'),
                    stderr=open(os.path.join(self.dir, "stderr"), mode='a'),
                    env=dict(os.environ, **self.env()))
            init_process.wait()

    def link(self, server):
        server.softhsm_conf = self.config_file()
