"""Python libknot interface."""

import ctypes
import sys


class KnotLookup(ctypes.Structure):
    """Libknot lookup return structure."""

    _fields_ = [('id', ctypes.c_int), ('name', ctypes.c_char_p)]


class KnotRdataDescriptor(ctypes.Structure):
    """Rdata descriptor structure."""

    _fields_ = [('block_types', ctypes.c_int * 8), ('name', ctypes.c_char_p)]


class Knot(object):
    """Basic libknot interface."""

    LIBKNOT = None
    LIBKNOT_VERSION = "@libknot_SOVERSION@"

    RCODE_NAMES = None

    STRERROR = None
    RDATA_DESC = None

    @classmethod
    def __init__(cls, path: str = None) -> None:
        """Loads shared libknot library.
           An explicit library path can be specified.
        """

        if cls.LIBKNOT:
            return

        if path is None:
            version = ""
            try:
                version = ".%u" % int(cls.LIBKNOT_VERSION)
            except Exception:
                pass

            if sys.platform == "darwin":
                path = "libknot%s.dylib" % version
            else:
                path = "libknot.so%s" % version

        cls.LIBKNOT = ctypes.cdll.LoadLibrary(path)

        cls.RCODE_NAMES = (KnotLookup * 32).in_dll(cls.LIBKNOT, "knot_rcode_names")

        cls.STRERROR = cls.LIBKNOT.knot_strerror
        cls.STRERROR.restype = ctypes.c_char_p
        cls.STRERROR.argtypes = [ctypes.c_int]

        cls.RDATA_DESC = cls.LIBKNOT.knot_get_rdata_descriptor
        cls.RDATA_DESC.restype = ctypes.POINTER(KnotRdataDescriptor)
        cls.RDATA_DESC.argtypes = [ctypes.c_ushort]

    @classmethod
    def rclass_str(cls, rclass: int) -> str:
        """Returns RRCLASS in text form."""

        if (rclass == 1):
            return "IN"
        elif (rclass == 3):
            return "CH"
        elif (rclass == 254):
            return "NONE"
        elif (rclass == 255):
            return "ANY"
        else:
            return "CLASS%i" % rclass

    @classmethod
    def rtype_str(cls, rtype: int) -> str:
        """Returns RRTYPE in text form."""

        descr = cls.RDATA_DESC(rtype).contents.name
        if descr:
            return descr.decode()
        else:
            return "TYPE%i" % rtype

    @classmethod
    def rcode_str(cls, rcode: int) -> str:
        """Returns RCODE in text form."""

        for item in cls.RCODE_NAMES:
            if item.name and item.id == rcode:
                return item.name.decode()
        return "RCODE%i" % rcode
