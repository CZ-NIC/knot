"""Libknot dname interface wrapper."""

import ctypes
import libknot


class KnotDname(object):
    """Libknot dname."""

    CAPACITY = 255
    CAPACITY_TXT = 1004

    DnameStorage = ctypes.c_char * CAPACITY
    DnameTxtStorage = ctypes.c_char * CAPACITY_TXT

    SIZE = None
    CHECK = None
    TO_STR = None
    FROM_STR = None

    data = None

    def __init__(self, dname_str: str = None, dname_wire: bytes = None) -> None:
        """Initializes a dname storage. Optionally initializes from a string or wire."""

        if not KnotDname.SIZE:
            libknot.Knot()

            KnotDname.SIZE = libknot.Knot.LIBKNOT.knot_dname_size
            KnotDname.SIZE.restype = ctypes.c_size_t
            KnotDname.SIZE.argtypes = [KnotDname.DnameStorage]

            KnotDname.CHECK = libknot.Knot.LIBKNOT.knot_dname_wire_check
            KnotDname.CHECK.restype = ctypes.c_int
            KnotDname.CHECK.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]

            KnotDname.TO_STR = libknot.Knot.LIBKNOT.knot_dname_to_str
            KnotDname.TO_STR.restype = ctypes.c_char_p
            KnotDname.TO_STR.argtypes = [KnotDname.DnameTxtStorage, KnotDname.DnameStorage, ctypes.c_size_t]

            KnotDname.FROM_STR = libknot.Knot.LIBKNOT.knot_dname_from_str
            KnotDname.FROM_STR.restype = ctypes.c_char_p
            KnotDname.FROM_STR.argtypes = [KnotDname.DnameStorage, ctypes.c_char_p, ctypes.c_size_t]

        if dname_str:
            self.data = KnotDname.DnameStorage()
            if not KnotDname.FROM_STR(self.data, dname_str.encode('utf-8'), KnotDname.CAPACITY):
                raise ValueError
        elif dname_wire:
            size = len(dname_wire)
            if size > KnotDname.CAPACITY:
                raise ValueError
            self.data = KnotDname.DnameStorage()
            ctypes.memmove(self.data, dname_wire, size)
            start = ctypes.cast(self.data, ctypes.POINTER(ctypes.c_char * size))[0]
            end = ctypes.cast(self.data, ctypes.POINTER(ctypes.c_char * size))[1]
            if KnotDname.CHECK(start, end, start) <= 0:
                raise ValueError

    def size(self):
        """Returns size of the stored dname."""

        if self.data:
            return KnotDname.SIZE(self.data)
        else:
            return 0

    def str(self) -> str:
        """Prints the stored dname in textual format."""

        if self.data:
            data_txt = KnotDname.DnameTxtStorage()
            if not KnotDname.TO_STR(data_txt, self.data, KnotDname.CAPACITY_TXT):
                raise ValueError
            return data_txt.value.decode("utf-8")
        else:
            return ""

    def wire(self) -> bytes:
        """Returns the dname in wire format."""

        if self.data:
            return self.data.value + b'\x00'
        else:
            return bytes()
