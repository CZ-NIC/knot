#!/usr/bin/env python3
# vim: et ts=4 sw=4 sts=4
#
# Dump content of zone timers database in user readable format.
#

import datetime
import lmdb
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
    def format_value(cls, id, value):
        timers = {
                # knot >= 1.6
                0x01: ("legacy_refresh", cls.format_timestamp),
                0x02: ("legacy_expire",  cls.format_timestamp),
                0x03: ("legacy_flush",   cls.format_timestamp),
                # knot >= 2.4
                0x80: ("soa_expire",     cls.format_seconds),
                0x81: ("last_flush",     cls.format_timestamp),
                0x82: ("last_refresh",   cls.format_timestamp),
                0x83: ("next_refresh",   cls.format_timestamp),
                # knot >= 2.6
                0x84: ("last_resalt",    cls.format_timestamp),
                0x85: ("next_ds_check",  cls.format_timestamp),
                # knot >= 2.8
                0x86: ("next_ds_push",   cls.format_timestamp),
                # knot >= 3.1
                0x87: ("catalog_member", cls.format_timestamp),
                0x88: ("notify_serial",  cls.format_notify_serial),
                # knot >= 3.2
                0x89: ("last_refresh_ok", cls.format_bool),
        }
        if id in timers:
            return (timers[id][0], timers[id][1](value))
        else:
            return ("%02x" % id, "%08x" % value)

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
            chunk = binary[:9]
            binary = binary[9:]
            id, value = struct.unpack("!BQ", chunk)
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
