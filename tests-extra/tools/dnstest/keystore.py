class KnotPEM(object):
    def __init__(self, id : str, ksk_only : bool = None, key_label : bool = None):
        self.id = id
        if ksk_only == None:
            self.ksk_only = True if id.endswith("ksk") else False
        else:
            self.ksk_only = ksk_only
        self.key_label = key_label

    @property
    def config(self):
        out = {
            "id": self.id,
            "backend": "pem",
            "config": self.id,
            "ksk-only": self.ksk_only
        }
        if self.key_label != None:
            out["key-label"] = self.key_label

        return out

class KnotPkcs11SoftHSM(object):
    def __init__(self, id : str, token : str, passwd : str, so_path : str = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", ksk_only : bool = None, key_label : bool = None):
        self.id = id
        self.token = token
        self.passwd = passwd
        self.so_path = so_path
        self.ksk_only = ksk_only
        self.key_label = key_label

    @property
    def config(self):
        out = {
            "id": self.id,
            "backend": "pkcs11",
            "config": f"pkcs11:token={self.token};pin-value={self.passwd} {self.so_path}"
        }
        if self.ksk_only != None:
            out["ksk_only"] = self.ksk_only
        if self.key_label != None:
            out["key-label"] = self.key_label

        return out


