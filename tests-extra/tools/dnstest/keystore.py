#!/usr/bin/env python3

import os
import shutil
import textwrap
from subprocess import Popen, check_output
from dnstest.context import Context
from dnstest.utils import *

class Keystore(object):
    def __init__(self, id: str, server = None, ksk_only: bool = None, key_label: bool = None):
        self.id = id
        self.server = server # Only KeystoreDflt uses it.
        self.ksk_only = ksk_only
        self.key_label = key_label

class KeystoreDflt(Keystore):
    def __init__(self, id: str, server, ksk_only: bool = None, key_label: bool = None):
        super().__init__(id, server, False, False)

    def config(self):
        return None

    def _config(self):
        return os.path.join(self.server.keydir, "keys")

    def backend(self):
        return None

    def _backend(self):
        return "pem"

    def env(self):
        return { }

    def clear(self):
        shutil.rmtree(self._config())

    def keys(self):
        return [name.removesuffix('.pem') for name in os.listdir(self._config())]

    def has_key(self, id: str):
        return id in self.keys()

class KeystorePEM(Keystore):
    def __init__(self, id: str, server = None, ksk_only: bool = None, key_label: bool = None):
        super().__init__(id, server, ksk_only, key_label)

    def config(self):
        return os.path.join(Context().test.out_dir, f"{self.backend()}-{self.id}")

    def backend(self):
        return "pem"

    def env(self):
        return { }

    def clear(self):
        shutil.rmtree(self.config())

    def keys(self):
        return [name.removesuffix('.pem') for name in os.listdir(self.config())]

    def has_key(self, id: str):
        return id in self.keys()

class KeystoreSoftHSM(Keystore):
    so_pin = "12345"

    def __init__(self, id: str, server = None, ksk_only: bool = None, key_label: bool = None,
                 token: str = None, passwd: str = None, so_path: str = None):
        super().__init__(id, server, ksk_only, key_label)
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

    def keys(self):
        urls = check_output(['p11tool', '--list-token-urls'],
                            env=dict(os.environ, **self.env())).decode('ascii')
        url = ssearch(urls, r'(pkcs11:.*SoftHSM.*)')

        # In case of concurrent access to SoftHSM, p11tool may fail or crash. Retry then.
        MAX_TRIES = 3
        for tries in range(MAX_TRIES):
            try:
                output = check_output(['p11tool', '-d 9999', '--login', '--set-pin', self.passwd, '--list-keys', url],
                                      env=dict(os.environ, **self.env()),
                                      stderr=open(Context().test.out_dir + "/p11tool.err", mode="a")).decode('ascii')

                return [key.removeprefix('ID: ').replace(":", "") for key in re.findall(r'(ID: .*)', output)]
            except CalledProcessError as e:
                # p11tool sets exit status to 2 if there aren't any keys in SoftHSM.
                if e.returncode == 2:
                    return []
                else:
                    if tries < MAX_TRIES - 1:
                        time.sleep(1)

        raise Failed("'p11tool --list-keys' failed")

    def has_key(self, id: str):
        return id in self.keys()

    def init(self, keystore=None):
        if not os.path.isdir(self.dir):
            os.makedirs(os.path.join(self.dir, "tokens"))
            with open(self.config_file(), "w") as conf_file:
                config = (
                    f"directories.tokendir = {self.dir}/tokens/\n"
                     "objectstore.backend = file\n"
                     "slots.removable = false\n"
                     "slots.mechanisms = ALL\n"
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
