import ctypes
import os
from typing import Optional

class _CapHeader(ctypes.Structure):
        _fields_ = [
                ("version", ctypes.c_uint32),
                ("pid", ctypes.c_int),
        ]

class _CapData(ctypes.Structure):
        _fields_ = [
                ("effective", ctypes.c_uint32),
                ("permitted", ctypes.c_uint32),
                ("inheritable", ctypes.c_uint32),
        ]

class LinuxSyscalls:
        PR_SET_DUMPABLE = 4
        PR_CAP_AMBIENT = 47
        PR_CAP_AMBIENT_CLEAR_ALL = 4

        MS_REC = 0x4000
        MS_PRIVATE = 0x40000

        _LINUX_CAPABILITY_VERSION_3 = 0x20080522
        _instance: Optional["LinuxSyscalls"] = None

        def __new__(cls) -> "LinuxSyscalls":
                if cls._instance is None:
                        inst = super().__new__(cls)
                        inst._libc = None
                        cls._instance = inst
                return cls._instance

        def _get_libc(self) -> ctypes.CDLL:
                if self._libc is None:
                        libc = ctypes.CDLL(None, use_errno=True)

                        libc.mount.argtypes = [
                                ctypes.c_char_p,
                                ctypes.c_char_p,
                                ctypes.c_char_p,
                                ctypes.c_ulong,
                                ctypes.c_void_p,
                        ]
                        libc.mount.restype = ctypes.c_int

                        libc.prctl.argtypes = [
                                ctypes.c_int,
                                ctypes.c_ulong,
                                ctypes.c_ulong,
                                ctypes.c_ulong,
                                ctypes.c_ulong,
                        ]
                        libc.prctl.restype = ctypes.c_int

                        libc.capset.argtypes = [
                                ctypes.POINTER(_CapHeader),
                                ctypes.POINTER(_CapData),
                        ]
                        libc.capset.restype = ctypes.c_int

                        self._libc = libc
                return self._libc

        @staticmethod
        def _raise_errno(detail: str) -> None:
                err = ctypes.get_errno()
                raise OSError(err, os.strerror(err), detail)

        @staticmethod
        def _encode_path(path: str | bytes | os.PathLike[str]) -> bytes:
                if isinstance(path, bytes):
                        return path
                return os.fsencode(path)

        def map_ids(self, inner_uid, outer_uid, inner_gid, outer_gid) -> None:
                map_data = (
                        ("/proc/self/setgroups", "deny\n"),
                        ("/proc/self/uid_map", f"{inner_uid} {outer_uid} 1\n"),
                        ("/proc/self/gid_map", f"{inner_gid} {outer_gid} 1\n")
                )

                for path, data in map_data:
                        with open(path, "w", encoding="utf-8") as f:
                                f.write(data)

        def become_root(self, outer_uid, outer_gid) -> None:
                self.map_ids(0, outer_uid, 0, outer_gid)

        def become_unprivileged(self, inner_uid, inner_gid) -> None:
                self.map_ids(inner_uid, 0, inner_gid, 0)

        def mount(
                self,
                source: str | bytes | os.PathLike[str] | None,
                target: str | bytes | os.PathLike[str],
                fstype: str | bytes | None,
                flags: int,
        ) -> None:
                libc = self._get_libc()
                src_b = self._encode_path(source) if source is not None else None
                tgt_b = self._encode_path(target)
                fst_b = self._encode_path(fstype) if fstype is not None else None

                ctypes.set_errno(0)
                if libc.mount(src_b, tgt_b, fst_b, flags, None) != 0:
                        self._raise_errno(f"mount({target!r})")

        def set_dumpable(self, value: int = 1) -> None:
                libc = self._get_libc()
                ctypes.set_errno(0)
                if libc.prctl(self.PR_SET_DUMPABLE, value, 0, 0, 0) != 0:
                        self._raise_errno("prctl(PR_SET_DUMPABLE)")

        def drop_all_capabilities(self) -> None:
                libc = self._get_libc()

                ctypes.set_errno(0)
                if libc.prctl(self.PR_CAP_AMBIENT, self.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0:
                        self._raise_errno("PR_CAP_AMBIENT_CLEAR_ALL")

                header = _CapHeader(version=self._LINUX_CAPABILITY_VERSION_3, pid=0)
                empty_caps = (_CapData * 2)()

                ctypes.set_errno(0)
                if libc.capset(ctypes.byref(header), empty_caps) != 0:
                        self._raise_errno("capset")
