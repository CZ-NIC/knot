"""Libknot server control interface wrapper."""

import ctypes
import enum
import warnings
import libknot


def load_lib(path: str = None) -> None:
    """Compatibility wrapper."""

    libknot.Knot(path)
    warnings.warn("libknot.control.load_lib() is deprecated, use libknot.Knot() instead", \
                  category=Warning, stacklevel=2)


class KnotCtlType(enum.IntEnum):
    """Libknot server control data unit types."""

    END = 0
    DATA = 1
    EXTRA = 2
    BLOCK = 3


class KnotCtlDataIdx(enum.IntEnum):
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
    FILTERS = 11


class KnotCtlData(object):
    """Libknot server control data unit."""

    DataArray = ctypes.c_char_p * len(KnotCtlDataIdx)

    def __init__(self) -> None:
        self.data = self.DataArray()

    def __str__(self) -> str:
        """Returns data unit in text form."""

        string = str()

        for idx in KnotCtlDataIdx:
            if self.data[idx]:
                if string:
                    string += ", "
                string += "%s = '%s'" % (idx.name, self.data[idx].decode())

        return string

    def __getitem__(self, index: KnotCtlDataIdx) -> str:
        """Data unit item getter."""

        value = self.data[index]
        return value.decode() if value else str()

    def __setitem__(self, index: KnotCtlDataIdx, value: str) -> None:
        """Data unit item setter."""

        self.data[index] = ctypes.c_char_p(value.encode()) if value != None else ctypes.c_char_p()


class KnotCtlError(Exception):
    """Libknot server control error."""

    def __init__(self, message: str, data: KnotCtlData = None) -> None:
        super().__init__()
        self.message = message
        self.data = data

    def __str__(self) -> str:
        out = "%s" % self.message
        if self.data:
            out += " (%s)" % self.data
        return out


class KnotCtlErrorConnect(KnotCtlError):
    """Control connection error."""


class KnotCtlErrorSend(KnotCtlError):
    """Control data send error."""


class KnotCtlErrorReceive(KnotCtlError):
    """Control data receive error."""


class KnotCtlErrorRemote(KnotCtlError):
    """Control error on the remote (server) side."""


class KnotCtl(object):
    """Libknot server control interface."""

    ALLOC = None
    FREE = None
    SET_TIMEOUT = None
    CONNECT = None
    CLOSE = None
    SEND = None
    RECEIVE = None

    def __init__(self) -> None:
        """Initializes a control interface instance."""

        if not KnotCtl.ALLOC:
            libknot.Knot()

            KnotCtl.ALLOC = libknot.Knot.LIBKNOT.knot_ctl_alloc
            KnotCtl.ALLOC.restype = ctypes.c_void_p

            KnotCtl.FREE = libknot.Knot.LIBKNOT.knot_ctl_free
            KnotCtl.FREE.argtypes = [ctypes.c_void_p]

            KnotCtl.SET_TIMEOUT = libknot.Knot.LIBKNOT.knot_ctl_set_timeout
            KnotCtl.SET_TIMEOUT.argtypes = [ctypes.c_void_p, ctypes.c_int]

            KnotCtl.CONNECT = libknot.Knot.LIBKNOT.knot_ctl_connect
            KnotCtl.CONNECT.restype = ctypes.c_int
            KnotCtl.CONNECT.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

            KnotCtl.CLOSE = libknot.Knot.LIBKNOT.knot_ctl_close
            KnotCtl.CLOSE.argtypes = [ctypes.c_void_p]

            KnotCtl.SEND = libknot.Knot.LIBKNOT.knot_ctl_send
            KnotCtl.SEND.restype = ctypes.c_int
            KnotCtl.SEND.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p]

            KnotCtl.RECEIVE = libknot.Knot.LIBKNOT.knot_ctl_receive
            KnotCtl.RECEIVE.restype = ctypes.c_int
            KnotCtl.RECEIVE.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

        self.obj = KnotCtl.ALLOC()

    def __del__(self) -> None:
        """Deallocates control interface instance."""

        KnotCtl.FREE(self.obj)

    def set_timeout(self, timeout: int) -> None:
        """Sets control socket operations timeout in seconds."""

        KnotCtl.SET_TIMEOUT(self.obj, timeout * 1000)

    def connect(self, path: str) -> None:
        """Connect to a specified control UNIX socket."""

        ret = KnotCtl.CONNECT(self.obj, path.encode())
        if ret != 0:
            err = libknot.Knot.STRERROR(ret)
            raise KnotCtlErrorConnect(err.decode())

    def close(self) -> None:
        """Disconnects from the current control socket."""

        KnotCtl.CLOSE(self.obj)

    def send(self, data_type: KnotCtlType, data: KnotCtlData = None) -> None:
        """Sends a data unit to the connected control socket."""

        ret = KnotCtl.SEND(self.obj, data_type,
                           data.data if data else ctypes.c_char_p())
        if ret != 0:
            err = libknot.Knot.STRERROR(ret)
            raise KnotCtlErrorSend(err.decode())

    def receive(self, data: KnotCtlData = None) -> KnotCtlType:
        """Receives a data unit from the connected control socket."""

        data_type = ctypes.c_uint()
        ret = KnotCtl.RECEIVE(self.obj, ctypes.byref(data_type),
                              data.data if data else ctypes.c_char_p())
        if ret != 0:
            err = libknot.Knot.STRERROR(ret)
            raise KnotCtlErrorReceive(err.decode())
        return KnotCtlType(data_type.value)

    def send_block(self, cmd: str, section: str = None, item: str = None,
                   identifier: str = None, zone: str = None, owner: str = None,
                   ttl: str = None, rtype: str = None, data: str = None,
                   flags: str = None, filters: str = None) -> None:
        """Sends a control query block."""

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
        query[KnotCtlDataIdx.FILTERS] = filters

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

    def receive_stats(self) -> dict:
        """Receives statistics answer and returns it as a structured dictionary."""

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
            raise KnotCtlErrorRemote(err_reply[KnotCtlDataIdx.ERROR], err_reply)

        return out

    def receive_block(self) -> dict:
        """Receives a control answer and returns it as a structured dictionary."""

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
            raise KnotCtlErrorRemote(err_reply[KnotCtlDataIdx.ERROR], err_reply)

        return out
