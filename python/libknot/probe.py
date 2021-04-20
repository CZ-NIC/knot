"""Libknot probe interface wrapper.

# Example:
from libknot.probe import *

load_lib("/w/knot/work4/src/.libs/libknot.so")

probe = KnotProbe("/tmp")

data = KnotProbeDataArray(8)
while (True):
    if probe.consume(data) > 0:
        for item in data:
            print(item)

"""

import ctypes
from ctypes import cdll, c_void_p, c_int, c_char_p, c_uint, c_ubyte, c_ushort
import enum
import sys
import socket

PROBE_ALLOC = None
PROBE_FREE = None
PROBE_SET_TIMEOUT = None
PROBE_CONNECT = None
PROBE_CLOSE = None
PROBE_SEND = None
PROBE_CONSUME = None
PROBE_ERROR = None


def load_lib(path=None):
    """Loads the libknot library."""

    if path is None:
        version = ""
        try:
            from libknot import LIBKNOT_VERSION
            version = ".%u" % int(LIBKNOT_VERSION)
        except:
            pass

        if sys.platform == "darwin":
            path = "libknot%s.dylib" % version
        else:
            path = "libknot.so%s" % version
    LIB = cdll.LoadLibrary(path)

    global PROBE_ALLOC
    PROBE_ALLOC = LIB.knot_probe_alloc
    PROBE_ALLOC.restype = c_void_p

    global PROBE_FREE
    PROBE_FREE = LIB.knot_probe_free
    PROBE_FREE.argtypes = [c_void_p]

    global PROBE_SET_CONSUMER
    PROBE_SET_CONSUMER = LIB.knot_probe_set_consumer
    PROBE_SET_CONSUMER.restype = c_int
    PROBE_SET_CONSUMER.argtypes = [c_void_p, c_char_p, c_ushort]

    global PROBE_CONSUME
    PROBE_CONSUME = LIB.knot_probe_consume
    PROBE_CONSUME.restype = c_int
    PROBE_CONSUME.argtypes = [c_void_p, c_void_p, c_ubyte, c_int]

    global PROBE_ERROR
    PROBE_ERROR = LIB.knot_strerror
    PROBE_ERROR.restype = c_char_p
    PROBE_ERROR.argtypes = [c_int]


class KnotProbeDataProto(enum.IntEnum):
    """Libknot probe transport protocol types."""

    UDP = 0
    TCP = 1
    TLS = 2
    HTTPS = 3
    QUIC = 4


class KnotProbeData(ctypes.Structure):
    """Libknot probe data unit."""

    ADDR_MAX_SIZE = 16
    QNAME_MAX_SIZE = 255

    _fields_ = [('ip', c_ubyte),
                ('proto', c_ubyte),
                ('local_addr', c_ubyte * ADDR_MAX_SIZE),
                ('local_port', c_ushort),
                ('remote_addr', c_ubyte * ADDR_MAX_SIZE),
                ('remote_port', c_ushort),
                ('reply_hdr_id', c_ushort), # Big endian
                ('reply_hdr_flag_qr', c_ubyte, 1),
                ('reply_hdr_opcode',  c_ubyte, 4),
                ('reply_hdr_flag_aa', c_ubyte, 1),
                ('reply_hdr_flag_tc', c_ubyte, 1),
                ('reply_hdr_flag_rd', c_ubyte, 1),
                ('reply_hdr_flag_ra', c_ubyte, 1),
                ('reply_hdr_flag_z',  c_ubyte, 1),
                ('reply_hdr_flag_ad', c_ubyte, 1),
                ('reply_hdr_flag_cd', c_ubyte, 1),
                ('reply_hdr_rcode',   c_ubyte, 4),
                ('reply_hdr_questions',   c_ushort), # Big endian
                ('reply_hdr_answers',     c_ushort), # Big endian
                ('reply_hdr_authorities', c_ushort), # Big endian
                ('reply_hdr_additionals', c_ushort), # Big endian
                ('reply_size', c_ushort),
                ('reply_rcode', c_ushort),
                ('reply_ede', c_ushort),
                ('tcp_rtt', c_uint),
                ('edns_options', c_uint),
                ('edns_payload', c_ushort),
                ('edns_version', c_ubyte),
                ('edns_present', c_ubyte, 1),
                ('edns_flag_do', c_ubyte, 1),
                ('_reserved_', c_ubyte, 6),
                ('query_hdr_id', c_ushort), # Big endian
                ('query_hdr_flag_qr', c_ubyte, 1),
                ('query_hdr_opcode',  c_ubyte, 4),
                ('query_hdr_flag_aa', c_ubyte, 1),
                ('query_hdr_flag_tc', c_ubyte, 1),
                ('query_hdr_flag_rd', c_ubyte, 1),
                ('query_hdr_flag_ra', c_ubyte, 1),
                ('query_hdr_flag_z',  c_ubyte, 1),
                ('query_hdr_flag_ad', c_ubyte, 1),
                ('query_hdr_flag_cd', c_ubyte, 1),
                ('query_hdr_rcode',   c_ubyte, 4),
                ('query_hdr_questions',   c_ushort), # Big endian
                ('query_hdr_answers',     c_ushort), # Big endian
                ('query_hdr_authorities', c_ushort), # Big endian
                ('query_hdr_additionals', c_ushort), # Big endian
                ('query_size', c_ushort),
                ('query_class', c_ushort),
                ('query_type', c_ushort),
                ('query_name_len', c_ubyte),
                ('query_name', c_ubyte * (QNAME_MAX_SIZE))]

    def addr_str(self, addr):
        if self.ip == 4:
            buffer = ctypes.create_string_buffer(4)
            ctypes.memmove(buffer, ctypes.addressof(addr), 4)
            return socket.inet_ntop(socket.AF_INET, buffer)
        else:
            return socket.inet_ntop(socket.AF_INET6, addr)

    def qname_str(self):
        string = str()
        pos = 0
        while pos < self.query_name_len:
            label_len = self.query_name[pos]
            if label_len == 0:
                if self.query_name_len == 1:
                    string += "."
                break
            pos += 1
            label_end = pos + label_len
            while pos < label_end:
                string += chr(self.query_name[pos])
                pos += 1
            string += "."
        return string

    def __str__(self):
        string = str()
        string += "%s@%u > " % (self.addr_str(self.remote_addr), self.remote_port)
        string += "%s@%u "   % (self.addr_str(self.local_addr), self.local_port)
        string += "%s " % ("UDP" if self.proto == 0 else "TCP")
        string += "qname: %s type: %u " % (self.qname_str(), self.query_type)
        string += "rcode %u" % self.reply_rcode
        if self.edns_present == 1 and self.edns_flag_do == 1:
            string += " DO"
        return string

class KnotProbeDataArray(object):
    """Libknot probe data unit array."""

    def __init__(self, size=1):
        if size < 1 or size > 255:
            raise ValueError
        DataArray = KnotProbeData * size
        self.data = DataArray()
        self.capacity = size
        self.used = 0

    def __getitem__(self, i):
        return self.data[i]

    def __len__(self):
        return self.used

    def __iter__(self):
        self.pos = 0
        return self

    def __next__(self):
        if self.used == 0 or self.pos == self.used:
            raise StopIteration
        else:
            data = self.data[self.pos]
            self.pos += 1
            return data

class KnotProbe(object):
    """Libknot probe interface."""

    def __init__(self, path="/run/knot", idx=1):
        if not PROBE_ALLOC:
            load_lib()
        self.obj = PROBE_ALLOC()

        PROBE_SET_CONSUMER(self.obj, path.encode(), idx)

    def __del__(self):
        PROBE_FREE(self.obj)

    def consume(self, data, timeout=1000):

        ret = PROBE_CONSUME(self.obj, data.data, data.capacity, timeout)
        if ret > 0:
            data.used = ret
        return ret
