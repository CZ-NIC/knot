#!/usr/bin/env python3

import os
import shutil
from subprocess import Popen
from dnstest.context import Context

class Keystore(object):
    def __init__(self, id: str, ksk_only: bool = None, key_label: bool = None):
        self.id = id
        self.ksk_only = ksk_only
        self.key_label = key_label

class KeystorePEM(Keystore):
    def __init__(self, id: str, ksk_only: bool = None, key_label: bool = None):
        super().__init__(id, ksk_only, key_label)

    @property
    def config(self):
        return os.path.join(Context().test.out_dir, f"{self.backend}-{self.id}")

    @property
    def backend(self):
        return "pem"

    def clear(self):
        shutil.rmtree(self.config)

class KeystoreSoftHSM(Keystore):
    so_pin = "12345"

    def __init__(self, id: str, ksk_only: bool = None, key_label: bool = None,
                 token: str = None, passwd: str = None, so_path: str = None):
        super().__init__(id, ksk_only, key_label)
        self.so_path = so_path if so_path else "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
        self.passwd = passwd if passwd else "1234"
        self.token = token if token else "knot"
        self.dir = os.path.join(Context().test.out_dir, f"{self.backend}-{self.id}")
        self.init()

    @property
    def config(self):
        return f"pkcs11:token={self.token};pin-value={self.passwd} {self.so_path}"

    @property
    def backend(self):
        return "pkcs11"

    @property
    def config_file(self):
        return os.path.join(self.dir, "softhsm.conf")

    def clear(self):
        shutil.rmtree(os.path.join(self.dir, "tokens"))

    def init(self, keystore=None):
        if not os.path.isdir(self.dir):
            os.makedirs(os.path.join(self.dir, "tokens"))
            with open(self.config_file, "w") as config_file:
                config = (
                    f"directories.tokendir = {self.dir}/tokens/\n"
                     "objectstore.backend = file\n"
                     "log.level = INFO\n"
                )
                config_file.write(config)

        if keystore:
            self.clear()
            shutil.copytree(os.path.join(keystore.dir, "tokens"), os.path.join(self.dir, "tokens"))
        else:
            init_process = Popen(
                ['softhsm2-util', '--init-token', '--free', f'--label={self.token}',
                 f'--pin={self.passwd}', f'--so-pin={self.so_pin}', f'--module={self.so_path}'],
                    stdout=open(os.path.join(self.dir, "stdout"), mode='a'),
                    stderr=open(os.path.join(self.dir, "stderr"), mode='a'),
                    env=dict(os.environ, SOFTHSM2_CONF=self.config_file))
            init_process.wait()

    def link(self, server):
        server.softhsm_conf = self.config_file
