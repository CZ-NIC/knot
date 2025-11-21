import os
import shutil
from subprocess import Popen

class KnotKeystore(object):
    def __init__(self, id : str, ksk_only : bool = None, key_label : bool = None):
        self.id = id
        self.ksk_only = ksk_only
        self.key_label = key_label

class KnotPEM(KnotKeystore):
    def __init__(self, id : str, ksk_only : bool = None, key_label : bool = None):
        KnotKeystore.__init__(self, id, ksk_only, key_label)
        if ksk_only == None:
            self.ksk_only = True if id.endswith("ksk") else False
        else:
            self.ksk_only = ksk_only
        self.key_label = key_label

    @property
    def config(self):
        return self.id

    @property
    def backend(self):
        return "pem"

    def clear(self, server):
        shutil.rmtree(os.path.join(server.keydir, self.id))

class KnotPkcs11SoftHSM(KnotKeystore):
    def __init__(self, id : str, token : str, passwd : str, so_path : str = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", ksk_only : bool = None, key_label : bool = None):
        KnotKeystore.__init__(self, id)
        self.token = token
        self.passwd = passwd
        self.so_path = so_path
        self.ksk_only = ksk_only
        self.key_label = key_label

    def __eq__(self, value):
        return self.id == value.id

    def __hash__(self):
        return hash(self.id)

    @property
    def config(self):
        return f"pkcs11:token={self.token};pin-value={self.passwd} {self.so_path}"

    @property
    def backend(self):
        return "pkcs11"

    def clear(self, server):
        Popen(
            ['softhsm2-util', '--delete-token', f'--token={self.token}', f'--pin={self.passwd}', '--so-pin=12345', f'--module={self.so_path}'],
            stdout=open(server.softhsm + "/stdout", mode='a'),
            stderr=open(server.softhsm + "/stderr", mode='a'),
            env=dict(os.environ,
                     SOFTHSM2_CONF=server.softhsm + "/softhsm.conf")
        ).wait()
        Popen(
            ['softhsm2-util', '--init-token', '--free', f'--label={self.token}', f'--pin={self.passwd}', '--so-pin=12345', f'--module={self.so_path}'],
            stdout=open(server.softhsm + "/stdout", mode='a'),
            stderr=open(server.softhsm + "/stderr", mode='a'),
            env=dict(os.environ,
                     SOFTHSM2_CONF=server.softhsm + "/softhsm.conf")
        ).wait()

class KnotPkcs11SoftHSMWrapper(object):
    def __init__(self, keystore : KnotPkcs11SoftHSM):
        self.keystore = keystore

    def __eq__(self, value):
        return self.keystore.token == value.keystore.token

    def __hash__(self):
        return hash(self.keystore.token)