"""Libknot probe interface wrapper."""

import ctypes
import enum
import socket
import libknot


class KnotProbeDataProto(enum.IntEnum):
    """Libknot probe transport protocol types."""

    UDP = 0
    TCP = 1
    TLS = 2
    HTTPS = 3
    QUIC = 4


class KnotProbeDataDNSHdr(ctypes.BigEndianStructure):
    """DNS message header."""

    _fields_ = [('id', ctypes.c_ushort),
                ('flag_qr', ctypes.c_ubyte, 1),
                ('opcode', ctypes.c_ubyte, 4),
                ('flag_aa', ctypes.c_ubyte, 1),
                ('flag_tc', ctypes.c_ubyte, 1),
                ('flag_rd', ctypes.c_ubyte, 1),
                ('flag_ra', ctypes.c_ubyte, 1),
                ('flag_z', ctypes.c_ubyte, 1),
                ('flag_ad', ctypes.c_ubyte, 1),
                ('flag_cd', ctypes.c_ubyte, 1),
                ('rcode', ctypes.c_ubyte, 4),
                ('questions', ctypes.c_ushort),
                ('answers', ctypes.c_ushort),
                ('authorities', ctypes.c_ushort),
                ('additionals', ctypes.c_ushort)]


class KnotProbeData(ctypes.Structure):
    """Libknot probe data unit."""

    ADDR_MAX_SIZE = 16
    QNAME_MAX_SIZE = 255

    EDE_NONE = 65535

    _fields_ = [('ip', ctypes.c_ubyte),
                ('proto', ctypes.c_ubyte),
                ('local_addr', ctypes.c_ubyte * ADDR_MAX_SIZE),
                ('local_port', ctypes.c_ushort),
                ('remote_addr', ctypes.c_ubyte * ADDR_MAX_SIZE),
                ('remote_port', ctypes.c_ushort),
                ('reply_hdr', KnotProbeDataDNSHdr),
                ('reply_size', ctypes.c_ushort),
                ('reply_rcode', ctypes.c_ushort),
                ('reply_ede', ctypes.c_ushort),
                ('tcp_rtt', ctypes.c_uint),
                ('edns_options', ctypes.c_uint),
                ('edns_payload', ctypes.c_ushort),
                ('edns_version', ctypes.c_ubyte),
                ('edns_present', ctypes.c_ubyte, 1),
                ('edns_flag_do', ctypes.c_ubyte, 1),
                ('_reserved_', ctypes.c_ubyte, 6),
                ('query_hdr', KnotProbeDataDNSHdr),
                ('query_size', ctypes.c_ushort),
                ('query_class', ctypes.c_ushort),
                ('query_type', ctypes.c_ushort),
                ('query_name_len', ctypes.c_ubyte),
                ('query_name', ctypes.c_ubyte * (QNAME_MAX_SIZE))]

    def addr_str(self, addr: ctypes.c_ubyte * ADDR_MAX_SIZE) -> str:
        """Converts IPv4 or IPv6 address from binary to text form."""

        if self.ip == 4:
            buffer = ctypes.create_string_buffer(4)
            ctypes.memmove(buffer, ctypes.addressof(addr), 4)
            return socket.inet_ntop(socket.AF_INET, buffer)
        else:
            return socket.inet_ntop(socket.AF_INET6, addr)

    def qname_str(self) -> str:
        """Returns QNAME in text form."""

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

    def __str__(self) -> str:
        """Returns data unit in pre-formatted simple text form."""

        string = str()
        string += "%s@%u > " % (self.addr_str(self.remote_addr), self.remote_port)
        string += "%s@%u "   % (self.addr_str(self.local_addr), self.local_port)
        string += "%s, " % ("UDP" if self.proto == 0 else "TCP")
        string += "%s %s" % (self.qname_str(), libknot.Knot.rtype_str(self.query_type))
        if self.edns_present == 1 and self.edns_flag_do == 1:
            string += " DO"
        string += ", %s" % libknot.Knot.rcode_str(self.reply_rcode)
        return string


class KnotProbeDataArray(object):
    """Libknot probe data unit array."""

    def __init__(self, size: int = 1) -> None:
        """Creates a data array of a given size."""

        if size < 1 or size > 255:
            raise ValueError
        data_array = KnotProbeData * size
        self.data = data_array()
        self.capacity = size
        self.used = 0
        self.pos = 0

    def __getitem__(self, i: int) -> KnotProbeData:
        """Returns a data unit at a specified position."""

        if i < 0 or i >= self.capacity:
            raise ValueError
        return self.data[i]

    def __len__(self) -> int:
        """Returns currently used size of the array."""

        return self.used

    def __iter__(self):
        """Initializes the array iterator."""

        self.pos = 0
        return self

    def __next__(self) -> KnotProbeData:
        """Increments the array iterator."""

        if self.used == 0 or self.pos == self.used:
            raise StopIteration
        else:
            data = self.data[self.pos]
            self.pos += 1
            return data


class KnotProbe(object):
    """Libknot probe consumer interface."""

    ALLOC = None
    FREE = None
    CONSUME = None
    SET_CONSUMER = None

    def __init__(self, path: str = "/run/knot", idx: int = 1) -> None:
        """Initializes a probe channel at a specified path with a channel index."""

        if not KnotProbe.ALLOC:
            libknot.Knot()

            KnotProbe.ALLOC = libknot.Knot.LIBKNOT.knot_probe_alloc
            KnotProbe.ALLOC.restype = ctypes.c_void_p

            KnotProbe.FREE = libknot.Knot.LIBKNOT.knot_probe_free
            KnotProbe.FREE.argtypes = [ctypes.c_void_p]

            KnotProbe.CONSUME = libknot.Knot.LIBKNOT.knot_probe_consume
            KnotProbe.CONSUME.restype = ctypes.c_int
            KnotProbe.CONSUME.argtypes = [ctypes.c_void_p, ctypes.c_void_p, \
                                          ctypes.c_ubyte, ctypes.c_int]

            KnotProbe.SET_CONSUMER = libknot.Knot.LIBKNOT.knot_probe_set_consumer
            KnotProbe.SET_CONSUMER.restype = ctypes.c_int
            KnotProbe.SET_CONSUMER.argtypes = [ctypes.c_void_p, ctypes.c_char_p, \
                                               ctypes.c_ushort]

        self.obj = KnotProbe.ALLOC()

        ret = KnotProbe.SET_CONSUMER(self.obj, path.encode(), idx)
        if ret != 0:
            err = libknot.Knot.STRERROR(ret)
            raise RuntimeError(err.decode())

    def __del__(self) -> None:
        """Deinitializes a probe channel."""

        KnotProbe.FREE(self.obj)

    def consume(self, data: KnotProbeDataArray, timeout: int = 1000) -> int:
        '''Consumes data units from a channel and stores them in data array.
           Returns the number of consumed data units.
        '''

        ret = KnotProbe.CONSUME(self.obj, data.data, data.capacity, timeout)
        if ret < 0:
            err = libknot.Knot.STRERROR(ret)
            raise RuntimeError(err.decode())
        data.used = ret
        return ret
