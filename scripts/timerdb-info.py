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

    # the order is significant
    TIMERS = [ "refresh", "expire", "flush", "transfer" ]

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
            if id > 0 and id <= len(cls.TIMERS):
                timers[id - 1] = value
        return timers

    @classmethod
    def format_date(cls, timestamp):
        if timestamp == 0:
            return "never"
        else:
            return datetime.datetime.fromtimestamp(timestamp).isoformat()

    @classmethod
    def format_line(cls, zone, timers):
        parts = [zone]
        for id, name in enumerate(cls.TIMERS):
            parts.append("%s %s" % (name, cls.format_date(timers.get(id, 0))))
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
