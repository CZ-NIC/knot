#!/usr/bin/env python3
# vim: et ts=4 sw=4 sts=4
#
# Dump content of zone timers database in user readable format.
#

import datetime
import lmdb
import socket
import struct
import sys

class TimerDBInfo:
    def __init__(self, path):
        self._path = path

    @classmethod
    def format_timestamp(cls, timestamp):
        if timestamp == 0:
            return "never"
        else:
            return datetime.datetime.fromtimestamp(timestamp).isoformat()

    @classmethod
    def format_bool(cls, value):
        return "yes" if value != 0 else "no"

    @classmethod
    def format_seconds(cls, value):
        return "%d" % value

    @classmethod
    def format_notify_serial(cls, value):
        if (value & (1 << 32)) == 0:
            return "none"
        else:
            return "%d" % (value & 0xffffffff)

    @classmethod
    def format_last_master(cls, value):
        offset = 4 if value[0] == socket.AF_INET else 16
        return socket.inet_ntop(value[0], value[-offset:])

    @classmethod
    def format_value(cls, id, value):
        timers = {
                # knot >= 1.6
                0x01: ("legacy_refresh",   8, cls.format_timestamp),
                0x02: ("legacy_expire",    8, cls.format_timestamp),
                0x03: ("legacy_flush",     8, cls.format_timestamp),
                # knot >= 2.4
                0x80: ("soa_expire",       8, cls.format_seconds),
                0x81: ("last_flush",       8, cls.format_timestamp),
                0x82: ("last_refresh",     8, cls.format_timestamp),
                0x83: ("next_refresh",     8, cls.format_timestamp),
                # knot >= 2.6
                0x84: ("legacy_resalt",    8, cls.format_timestamp),
                0x85: ("next_ds_check",    8, cls.format_timestamp),
                # knot >= 2.8
                0x86: ("next_ds_push",     8, cls.format_timestamp),
                # knot >= 3.1
                0x87: ("catalog_member",   8, cls.format_timestamp),
                0x88: ("notify_serial",    8, cls.format_notify_serial),
                # knot >= 3.2
                0x89: ("last_refresh_ok",  8, cls.format_bool),
                0x8a: ("next_expire",      8, cls.format_timestamp),
                # knot >= 3.3
                0x8b: ("last_master",     28, cls.format_last_master),
                0x8c: ("master_pin_hit",   8, cls.format_timestamp),
        }
        if id in timers:
            return (timers[id][0], timers[id][2](value)) if value != None else timers[id][1]
        else:
            return ("%02x" % id, "%08x" % value) if value != None else 0

    @classmethod
    def parse_dname(cls, dname):
        labels = []
        while dname[0] != 0:
            llen = dname[0]
            label = dname[1:llen+1].decode("utf-8")
            dname = dname[llen+1:]
            labels.append(label)
        return ".".join(labels)

    @classmethod
    def parse_timers(cls, binary):
        timers = {}
        while len(binary) > 0:
            id_chunk = binary[:1]
            binary = binary[1:]
            id = struct.unpack("!B", id_chunk)[0]
            val_len = cls.format_value(id, None)
            if val_len == 8:
                val_chunk = binary[:val_len]
                value = struct.unpack("!Q", val_chunk)[0]
            else:
                value = binary[:val_len]
            binary = binary[val_len:]
            timers[id] = value
        return timers

    @classmethod
    def format_line(cls, zone, timers):
        parts = [zone]
        for id, value in timers.items():
            parts.append("%s: %s" % cls.format_value(id, value))
        return " | ".join(parts)

    def run(self):
        with lmdb.open(self._path, readonly=True) as db:
            with db.begin() as txn:
                cursor = txn.cursor()
                for key, value in cursor:
                    zone = self.parse_dname(key)
                    timers = self.parse_timers(value)
                    print(self.format_line(zone, timers))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: %s <timerdb-path>" % sys.argv[0], file=sys.stderr)
        sys.exit(1)
    path = sys.argv[1]
    app = TimerDBInfo(path)
    app.run()
