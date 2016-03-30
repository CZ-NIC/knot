"""Libknot server control interface wrapper.

Example:
    ctl = KnotCtl()
    ctl.connect("/var/run/knot/knot.sock")

    query = KnotCtlData()
    query[KnotCtlDataIdx.COMMAND] = "conf-read"
    query[KnotCtlDataIdx.SECTION] = "zone"

    ctl.send(KnotCtlType.DATA, query)
    ctl.send(KnotCtlType.BLOCK)

    while True:
        reply = KnotCtlData()
        reply_type = ctl.receive(reply)

        if reply_type is KnotCtlType.DATA:
            print("--- NEXT ---")
            for i in KnotCtlDataIdx:
                if reply[i]:
                    print("%s: %s" % (i.name, reply[i]))
        elif reply_type is KnotCtlType.EXTRA:
            if reply[KnotCtlDataIdx.TYPE]:
                print(reply[KnotCtlDataIdx.TYPE] + ": " +
                      reply[KnotCtlDataIdx.DATA])
            elif reply[KnotCtlDataIdx.DATA]:
                print("DATA: " + reply[KnotCtlDataIdx.DATA])
        else:
            break

    ctl.send(KnotCtlType.END)
    ctl.close()
"""

from ctypes import cdll, c_void_p, c_int, c_char_p, c_uint, byref
from enum import IntEnum

LIB = cdll.LoadLibrary('libknot.so.2')

CTL_ALLOC = LIB.knot_ctl_alloc
CTL_ALLOC.restype = c_void_p

CTL_FREE = LIB.knot_ctl_free
CTL_FREE.argtypes = [c_void_p]

CTL_SET_TIMEOUT = LIB.knot_ctl_set_timeout
CTL_SET_TIMEOUT.argtypes = [c_void_p, c_int]

CTL_CONNECT = LIB.knot_ctl_connect
CTL_CONNECT.restype = c_int
CTL_CONNECT.argtypes = [c_void_p, c_char_p]

CTL_CLOSE = LIB.knot_ctl_close
CTL_CLOSE.argtypes = [c_void_p]

CTL_SEND = LIB.knot_ctl_send
CTL_SEND.restype = c_int
CTL_SEND.argtypes = [c_void_p, c_uint, c_void_p]

CTL_RECEIVE = LIB.knot_ctl_receive
CTL_RECEIVE.restype = c_int
CTL_RECEIVE.argtypes = [c_void_p, c_void_p, c_void_p]

CTL_ERROR = LIB.knot_strerror
CTL_ERROR.restype = c_char_p
CTL_ERROR.argtypes = [c_int]


class KnotCtlType(IntEnum):
    """Libknot server control data unit types."""

    END = 0
    DATA = 1
    EXTRA = 2
    BLOCK = 3


class KnotCtlDataIdx(IntEnum):
    """Libknot server control data unit indices."""

    COMMAND = 0
    FLAGS = 1
    ERROR = 2
    SECTION = 3
    ITEM = 4
    ID = 5
    ZONE = 6
    OWNER = 7
    TTL = 8
    TYPE = 9
    DATA = 10


class KnotCtlData(object):
    """Libknot server control data unit."""

    DataArray = c_char_p * len(KnotCtlDataIdx)

    def __init__(self):
        self.data = self.DataArray()

    def __getitem__(self, index):
        """Data unit item getter.

        @type index: KnotCtlDataIdx
        @rtype: str
        """

        value = self.data[index]
        if not value:
            value = str()
        return value if isinstance(value, str) else value.decode()

    def __setitem__(self, index, value):
        """Data unit item setter.

        @type index: KnotCtlDataIdx
        @type value: str
        """

        self.data[index] = c_char_p(value.encode())

class KnotCtl(object):
    """Libknot server control interface."""

    def __init__(self):
        self.obj = CTL_ALLOC()

    def __del__(self):
        CTL_FREE(self.obj)

    def set_timeout(self, timeout):
        """Sets control socket operations timeout in seconds.

        @type timeout: int
        """

        CTL_SET_TIMEOUT(self.obj, timeout * 1000)

    def connect(self, path):
        """Connect to a specified control UNIX socket.

        @type path: str
        """

        ret = CTL_CONNECT(self.obj, path.encode())
        if ret != 0:
            err = CTL_ERROR(ret)
            raise Exception(err if isinstance(err, str) else err.decode())

    def close(self):
        """Disconnects from the current control socket."""

        CTL_CLOSE(self.obj)

    def send(self, data_type, data=None):
        """Sends a data unit to the connected control socket.

        @type data_type: KnotCtlType
        @type data: KnotCtlData
        """

        ret = CTL_SEND(self.obj, data_type,
                       data.data if data else c_char_p())
        if ret != 0:
            err = CTL_ERROR(ret)
            raise Exception(err if isinstance(err, str) else err.decode())

    def receive(self, data=None):
        """Receives a data unit from the connected control socket.

        @type data: KnotCtlData
        @rtype: KnotCtlType
        """

        data_type = c_uint()
        ret = CTL_RECEIVE(self.obj, byref(data_type),
                          data.data if data else c_char_p())
        if ret != 0:
            err = CTL_ERROR(ret)
            raise Exception(err if isinstance(err, str) else err.decode())
        return KnotCtlType(data_type.value)
