"""Libknot server control interface wrapper.

Example:
    import json
    from libknot.control import *

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

import sys
from ctypes import cdll, c_void_p, c_int, c_char_p, c_uint, byref
from enum import IntEnum

CTL_ALLOC = None
CTL_FREE = None
CTL_SET_TIMEOUT = None
CTL_CONNECT = None
CTL_CLOSE = None
CTL_SEND = None
CTL_RECEIVE = None
CTL_ERROR = None


def load_lib(path=None):
    """Loads the libknot library."""

    if path is None:
        path = "libknot.dylib" if sys.platform == "darwin" else "libknot.so"
    LIB = cdll.LoadLibrary(path)

    global CTL_ALLOC
    CTL_ALLOC = LIB.knot_ctl_alloc
    CTL_ALLOC.restype = c_void_p

    global CTL_FREE
    CTL_FREE = LIB.knot_ctl_free
    CTL_FREE.argtypes = [c_void_p]

    global CTL_SET_TIMEOUT
    CTL_SET_TIMEOUT = LIB.knot_ctl_set_timeout
    CTL_SET_TIMEOUT.argtypes = [c_void_p, c_int]

    global CTL_CONNECT
    CTL_CONNECT = LIB.knot_ctl_connect
    CTL_CONNECT.restype = c_int
    CTL_CONNECT.argtypes = [c_void_p, c_char_p]

    global CTL_CLOSE
    CTL_CLOSE = LIB.knot_ctl_close
    CTL_CLOSE.argtypes = [c_void_p]

    global CTL_SEND
    CTL_SEND = LIB.knot_ctl_send
    CTL_SEND.restype = c_int
    CTL_SEND.argtypes = [c_void_p, c_uint, c_void_p]

    global CTL_RECEIVE
    CTL_RECEIVE = LIB.knot_ctl_receive
    CTL_RECEIVE.restype = c_int
    CTL_RECEIVE.argtypes = [c_void_p, c_void_p, c_void_p]

    global CTL_ERROR
    CTL_ERROR = LIB.knot_strerror
    CTL_ERROR.restype = c_char_p
    CTL_ERROR.argtypes = [c_int]


class KnotCtlError(Exception):
    """Libknot server control error."""

    def __init__(self, message, data=None):
        """
        @type message: str
        @type data: KnotCtlData
        """

        self.message = message
        self.data = data

    def __str__(self):
        return "%s (data: %s)" % (self.message, self.data)


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
    FILTER = 11


class KnotCtlData(object):
    """Libknot server control data unit."""

    DataArray = c_char_p * len(KnotCtlDataIdx)

    def __init__(self):
        self.data = self.DataArray()

    def __str__(self):
        string = str()

        for idx in KnotCtlDataIdx:
            if self.data[idx]:
                if string:
                    string += ", "
                string += "%s = %s" % (idx.name, self.data[idx])

        return string

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
        if not CTL_ALLOC:
            load_lib()
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
            raise KnotCtlError(err if isinstance(err, str) else err.decode())

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
            raise KnotCtlError(err if isinstance(err, str) else err.decode())

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
            raise KnotCtlError(err if isinstance(err, str) else err.decode())
        return KnotCtlType(data_type.value)

    def send_block(self, cmd, section=None, item=None, identifier=None, zone=None,
                   owner=None, ttl=None, rtype=None, data=None, flags=None,
                   filter=None):
        """Sends a control query block.

        @type cmd: str
        @type section: str
        @type item: str
        @type identifier: str
        @type zone: str
        @type owner: str
        @type ttl: str
        @type rtype: str
        @type data: str
        @type filter: str
        """

        query = KnotCtlData()
        query[KnotCtlDataIdx.COMMAND] = cmd
        query[KnotCtlDataIdx.SECTION] = section
        query[KnotCtlDataIdx.ITEM] = item
        query[KnotCtlDataIdx.ID] = identifier
        query[KnotCtlDataIdx.ZONE] = zone
        query[KnotCtlDataIdx.OWNER] = owner
        query[KnotCtlDataIdx.TTL] = ttl
        query[KnotCtlDataIdx.TYPE] = rtype
        query[KnotCtlDataIdx.DATA] = data
        query[KnotCtlDataIdx.FLAGS] = flags
        query[KnotCtlDataIdx.FILTER] = filter

        self.send(KnotCtlType.DATA, query)
        self.send(KnotCtlType.BLOCK)

    def _receive_conf(self, out, reply):

        section = reply[KnotCtlDataIdx.SECTION]
        ident = reply[KnotCtlDataIdx.ID]
        item = reply[KnotCtlDataIdx.ITEM]
        data = reply[KnotCtlDataIdx.DATA]

        # Add the section if not exists.
        if section not in out:
            out[section] = dict()

        # Add the identifier if not exists.
        if ident and ident not in out[section]:
            out[section][ident] = dict()

        # Return if no item/value.
        if not item:
            return

        item_level = out[section][ident] if ident else out[section]

        # Treat alone identifier item differently.
        if item in ["id", "domain", "target"]:
            if data not in out[section]:
                out[section][data] = dict()
        else:
            if item not in item_level:
                item_level[item] = list()

            if data:
                item_level[item].append(data)

    def _receive_zone_status(self, out, reply):

        zone = reply[KnotCtlDataIdx.ZONE]
        rtype = reply[KnotCtlDataIdx.TYPE]
        data = reply[KnotCtlDataIdx.DATA]

        # Add the zone if not exists.
        if zone not in out:
            out[zone] = dict()

        out[zone][rtype] = data

    def _receive_zone(self, out, reply):

        zone = reply[KnotCtlDataIdx.ZONE]
        owner = reply[KnotCtlDataIdx.OWNER]
        ttl = reply[KnotCtlDataIdx.TTL]
        rtype = reply[KnotCtlDataIdx.TYPE]
        data = reply[KnotCtlDataIdx.DATA]

        # Add the zone if not exists.
        if zone not in out:
            out[zone] = dict()

        if owner not in out[zone]:
            out[zone][owner] = dict()

        if rtype not in out[zone][owner]:
            out[zone][owner][rtype] = dict()

        # Add the key/value.
        out[zone][owner][rtype]["ttl"] = ttl

        if not "data" in out[zone][owner][rtype]:
            out[zone][owner][rtype]["data"] = [data]
        else:
            out[zone][owner][rtype]["data"].append(data)

    def _receive_stats(self, out, reply):

        zone = reply[KnotCtlDataIdx.ZONE]
        section = reply[KnotCtlDataIdx.SECTION]
        item = reply[KnotCtlDataIdx.ITEM]
        idx = reply[KnotCtlDataIdx.ID]
        data = int(reply[KnotCtlDataIdx.DATA])

        # Add the zone if not exists.
        if zone:
            if "zone" not in out:
                out["zone"] = dict()

            if zone not in out["zone"]:
                out["zone"][zone] = dict()

        section_level = out["zone"][zone] if zone else out

        if section not in section_level:
            section_level[section] = dict()

        if idx:
            if item not in section_level[section]:
                section_level[section][item] = dict()

            section_level[section][item][idx] = data
        else:
            section_level[section][item] = data

    def receive_stats(self):
        """Receives statistics answer and returns it as a structured dictionary.

        @rtype: dict
        """

        out = dict()
        err_reply = None

        while True:
            reply = KnotCtlData()
            reply_type = self.receive(reply)

            # Stop if not data type.
            if reply_type not in [KnotCtlType.DATA, KnotCtlType.EXTRA]:
                break

            # Check for an error.
            if reply[KnotCtlDataIdx.ERROR]:
                err_reply = reply
                continue

            self._receive_stats(out, reply)

        if err_reply:
            raise KnotCtlError(err_reply[KnotCtlDataIdx.ERROR], err_reply)

        return out

    def receive_block(self):
        """Receives a control answer and returns it as a structured dictionary.

        @rtype: dict
        """

        out = dict()
        err_reply = None

        while True:
            reply = KnotCtlData()
            reply_type = self.receive(reply)

            # Stop if not data type.
            if reply_type not in [KnotCtlType.DATA, KnotCtlType.EXTRA]:
                break

            # Check for an error.
            if reply[KnotCtlDataIdx.ERROR]:
                err_reply = reply
                continue

            # Check for config data.
            if reply[KnotCtlDataIdx.SECTION]:
                self._receive_conf(out, reply)
            # Check for zone data.
            elif reply[KnotCtlDataIdx.ZONE]:
                if reply[KnotCtlDataIdx.OWNER]:
                    self._receive_zone(out, reply)
                else:
                    self._receive_zone_status(out, reply)
            else:
                continue

        if err_reply:
            raise KnotCtlError(err_reply[KnotCtlDataIdx.ERROR], err_reply)

        return out
