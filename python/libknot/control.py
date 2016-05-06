"""Libknot server control interface wrapper.

Example:
    ctl = KnotCtl()
    ctl.connect("/var/run/knot/knot.sock")

    try:
        ctl.send_block(cmd="conf-begin")
        resp = ctl.receive_block()

        ctl.send_block(cmd="conf-set", section="zone", item="domain", data="test")
        resp = ctl.receive_block()

        ctl.send_block(cmd="conf-commit")
        resp = ctl.receive_block()

        ctl.send_block(cmd="conf-read", section="zone", item="domain")
        resp = ctl.receive_block()
        print(json.dumps(resp, indent=4))
    finally:
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

        self.data[index] = c_char_p(value.encode()) if value else c_char_p()

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

    def send_block(self, cmd, section=None, identifier=None, item=None, zone=None, data=None):
        """Sends a control query block.

        @type cmd: str
        @type section: str
        @type item: str
        @type identifier: str
        @type zone: str
        @type data: str
        """

        query = KnotCtlData()
        query[KnotCtlDataIdx.COMMAND] = cmd
        query[KnotCtlDataIdx.SECTION] = section
        query[KnotCtlDataIdx.ITEM] = item
        query[KnotCtlDataIdx.ID] = identifier
        query[KnotCtlDataIdx.ZONE] = zone
        query[KnotCtlDataIdx.DATA] = data

        self.send(KnotCtlType.DATA, query)
        self.send(KnotCtlType.BLOCK)

    def receive_block(self):
        """Receives a control answer and returns it as a structured dictionary.

        @rtype: dict
        """

        out = dict()

        while True:
            reply = KnotCtlData()
            reply_type = self.receive(reply)

            # Stop if not data type.
            if reply_type not in [KnotCtlType.DATA, KnotCtlType.EXTRA]:
                break

            # Check for an error.
            if reply[KnotCtlDataIdx.ERROR]:
                raise Exception(reply[KnotCtlDataIdx.ERROR])

            # Check for config data.
            if reply[KnotCtlDataIdx.SECTION]:
                ident = reply[KnotCtlDataIdx.ID]
                key = reply[KnotCtlDataIdx.ITEM]
            # Check for zone data.
            elif reply[KnotCtlDataIdx.ZONE]:
                ident = reply[KnotCtlDataIdx.ZONE]
                key = reply[KnotCtlDataIdx.TYPE]
            else:
                continue

            section = reply[KnotCtlDataIdx.SECTION]
            data = reply[KnotCtlDataIdx.DATA]

            # Add the section if not exists.
            if section:
                if section not in out:
                    out[section] = dict()

            level1 = out[section] if section else out

            # Add the identifier if not exists.
            if ident:
                if ident not in level1:
                    level1[ident] = dict()

            level2 = level1[ident] if ident else level1

            # Add the key/value.
            if key:
                # Treat alone identifier item differently.
                if reply[KnotCtlDataIdx.SECTION] and key in ["id", "domain", "target"]:
                    level1[data] = dict()
                else:
                    if key not in level2:
                        level2[key] = list()

                    if data:
                        level2[key].append(data)

        return out
