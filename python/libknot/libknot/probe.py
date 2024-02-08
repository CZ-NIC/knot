"""Libknot probe interface wrapper."""

import ctypes
import datetime
import enum
import socket
import libknot


class KnotProbeDataProto(enum.IntEnum):
    """Libknot probe transport protocol types."""

    UDP = 0
    TCP = 1
    QUIC = 2
    TLS = 3
    HTTPS = 4


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
        """Returns the data unit in a pre-formatted text form."""

        return self.str()

    def str(self, timestamp: bool = True, color: bool = True) -> str:
        """Returns the data unit in a pre-formatted text form with customization."""

        RST = "\x1B[0m"
        BOLD = "\x1B[1m"
        UNDR = "\x1B[4m"
        RED = "\x1B[31m"
        GRN = "\x1B[32m"
        ORG = "\x1B[33m"
        YELW = "\x1B[93m"
        MGNT = "\x1B[35m"
        CYAN = "\x1B[36m"

        def COL(string, color_str, active=color):
            return str(string) if not active else color_str + str(string) + RST

        string = str()
        if timestamp:
            string += "%s " % COL(datetime.datetime.now().time(), YELW)
        if self.ip != 0:
            string += "%s -> %s, " % (COL(self.addr_str(self.remote_addr), UNDR),
                                      COL(self.addr_str(self.local_addr), UNDR))
            string += "port %u -> %u " % (self.remote_port, self.local_port)
        else:
            string += "%s, " % COL("UNIX", UNDR)
        if self.proto == KnotProbeDataProto.UDP:
            string += COL("UDP", GRN)
        elif self.proto == KnotProbeDataProto.TCP:
            string += COL("TCP", RED)
        elif self.proto == KnotProbeDataProto.QUIC:
            string += COL("QUIC", ORG)
        else:
            string += COL("TLS", YELW)
        if self.tcp_rtt > 0:
            string += ", RTT %.2f ms" % (self.tcp_rtt / 1000)
        string += "\n ID %u, " % self.query_hdr.id
        if self.query_hdr.opcode == 0:
            string += "QUERY"
        elif self.query_hdr.opcode == 4:
            string += COL("NOTIFY", MGNT)
        elif self.query_hdr.opcode == 5:
            string += COL("UPDATE", MGNT)
        else:
            string += COL("OPCODE%i" % self.query_hdr.opcode, MGNT)
        string += ", "
        string += COL("%s %s %s" % (self.qname_str(),
                                    libknot.Knot.rclass_str(self.query_class),
                                    libknot.Knot.rtype_str(self.query_type)), BOLD)
        if self.edns_present == 1:
            string += ", EDNS %i B" % self.edns_payload
            if self.edns_flag_do == 1:
                string += ", " + COL("DO", BOLD)
            if (self.edns_options & (1 << 3)) != 0:
                string += ", NSID"
            if (self.edns_options & (1 << 8)) != 0:
                string += ", ECS"
            if (self.edns_options & (1 << 10)) != 0:
                string += ", COOKIE"
        string += ", " + COL("%u B" % self.query_size, CYAN)
        if self.reply_size == 0:
            string += " -> %s" % COL("DROPPED", RED)
            return string
        string += " -> %s" % COL(libknot.Knot.rcode_str(self.reply_rcode), BOLD)
        if (self.reply_ede != libknot.probe.KnotProbeData.EDE_NONE):
            string += ", EDE %u" % self.reply_ede
        if self.reply_hdr.flag_aa != 0:
            string += ", " + COL("AA", BOLD)
        if self.reply_hdr.flag_tc != 0:
            string += ", " + COL("TC", BOLD)
        if self.reply_hdr.answers > 0:
            string += ", %u ANS" % self.reply_hdr.answers
        if self.reply_hdr.authorities > 0:
            string += ", %u AUT" % self.reply_hdr.authorities
        if self.reply_hdr.additionals > 0:
            string += ", %u ADD" % self.reply_hdr.additionals
        string += ", " + COL("%u B" % self.reply_size, CYAN)
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
