#!/usr/bin/env python3
# Copyright (C) CZ.NIC, z.s.p.o. and contributors
# SPDX-License-Identifier: GPL-2.0-or-later
# For more information, see <https://www.knot-dns.cz/>

"""Script for resolving ALIAS records in zones stored in Redis using local resolver."""

# requirements redis[hiredis]
from argparse import ArgumentError, ArgumentParser
from concurrent.futures import ProcessPoolExecutor
from contextlib import contextmanager
from enum import IntEnum
from functools import partial
from multiprocessing import Lock
from re import sub
from redis import Redis
from redis.exceptions import ConnectionError, ResponseError, TimeoutError
from socket import AF_INET, AF_INET6, SOCK_DGRAM, gaierror, getaddrinfo, inet_pton
from sys import exit, stderr

class RRType(IntEnum):
    A = 1
    SOA = 6
    AAAA = 28
    ALIAS = 65401

class Stats:
    new = 0
    updated = 0
    resolved = 0
    ipv4 = 0
    ipv6 = 0
    not_found = 0

    def __str__(self):
        return \
            f'Zones:   {self.new + self.updated}\t(new: {self.new}, updated: {self.updated})\n' + \
            f'Aliases: {self.resolved + self.not_found}\t(resolved: {self.resolved}, unknown: {self.not_found})\n' + \
            f'Records: {self.ipv4 + self.ipv6}\t(A: {self.resolved}, AAAA: {self.ipv6})'

    def __add__(self, rhs):
        self.new += rhs.new
        self.updated += rhs.updated
        self.resolved += rhs.resolved
        self.ipv4 += rhs.ipv4
        self.ipv6 += rhs.ipv6
        self.not_found += rhs.not_found

        return self

stdout_lock = Lock()

def arg_parser():
    parser = ArgumentParser(
        exit_on_error=False,
        prog="redis-unalias.py",
        description="Resolves ALIAS records in all zones of the input instance "
            "into the output instance"
    )

    # required positional arguments
    parser.add_argument(
        "input_instance",
        type=int,
        help="zone instance that converts ALIAS from",
    )
    parser.add_argument(
        "output_instance",
        type=int,
        help="zone instance that converts ALIAS to",
    )

    # redis connection
    redis_group = parser.add_argument_group("connection")
    redis_group.add_argument(
        "-a", "--addr",
        default="localhost",
        help="redis-server address",
    )
    redis_group.add_argument(
        "-p", "--port",
        type=int,
        default=6379,
        help="redis-server port",
    )

    # TLS settings
    tls_group = parser.add_argument_group("TLS")
    tls_group.add_argument(
        "-t", "--tls",
        action="store_true",
        help="use transport layer security (TLS)",
    )
    tls_group.add_argument(
        "-C", "--tls-cert",
        dest="tls_cert",
        help="path to a client certificate",
    )
    tls_group.add_argument(
        "-K", "--tls-key",
        dest="tls_key",
        help="path to a client key",
    )
    tls_group.add_argument(
        "-A", "--tls-ca",
        dest="tls_ca",
        help="path to a trusted CA certificates used to verify the server",
    )
    tls_group.add_argument(
        "-i", "--tls-insecure",
        action="store_const",
        const="none",
        default="required",
        help="disable client TLS validation",
    )

    # behavior
    behavior_group = parser.add_argument_group("execution")
    behavior_group.add_argument(
        "-d", "--dry-run",
        action="store_true",
        help="print the transaction instead of commiting",
    )
    behavior_group.add_argument(
        "-s", "--print-stats",
        action="store_true",
        help="print statistics at the end",
    )

    return parser

def bytes_to_int(bytes):
    return int.from_bytes(bytes, signed=False)

def int_to_bytes(val):
    return bytes([val])

def txn_to_str(txn):
    return txn[0] * 10 + txn[1]

def dname_to_str(wire):
    res = ""

    dname_len = len(wire)
    if dname_len == 0:
        return res

    label_len = 0
    for i in range(0, dname_len):
        if label_len == 0:
            label_len = wire[i]
            if len(res) > 0 or dname_len == 1:
                res += '.'
            continue

        c = chr(wire[i])
        if c.isalnum() or c == '-':
            res += c
        else:
            res += f"\\{wire[i]:03}"

        label_len -= 1

    return res

def af_to_rtype(af):
    if af == AF_INET:
        return RRType.A.value
    elif af == AF_INET6:
        return RRType.AAAA.value
    else:
        raise Exception('Unsupported type')

def rdata_to_dname_list(dname):
    processing = 0
    out = []
    while processing < len(dname):
        size = int.from_bytes(dname[processing : processing + 2], "little", signed=False)
        if size == 0:
            break
        wire = dname[processing + 2 : processing + size + 2]
        out.append(dname_to_str(wire))
        processing += size + 2
    return out

def get_serial(rdata):
    wire_serial = rdata[len(rdata) - 21 : len(rdata) - 17]
    return int.from_bytes(wire_serial, byteorder='big', signed=False)

def set_serial(rdata, serial):
    b = bytearray(rdata)
    b[len(b) - 21 : len(b) - 17] = serial.to_bytes(4, 'big')
    return bytes(b)

@contextmanager
def knot_zone_transaction(conn, zone, inst, dryrun):
    txn = None
    try:
        instance = int_to_bytes(inst)
        txn = conn.execute_command('KNOT_BIN.ZONE.BEGIN', zone, instance)
        yield txn
    except:
        if txn:
            conn.execute_command('KNOT_BIN.ZONE.ABORT', zone, txn)
        raise
    else:
        if dryrun:
            conn.execute_command('KNOT_BIN.ZONE.ABORT', zone, txn)
        else:
            conn.execute_command('KNOT_BIN.ZONE.COMMIT', zone, txn)

@contextmanager
def knot_upd_transaction(conn, zone, inst, dryrun):
    txn = None
    try:
        instance = int_to_bytes(inst)
        txn = conn.execute_command('KNOT_BIN.UPD.BEGIN', zone, instance)
        yield txn
    except:
        if txn:
            conn.execute_command('KNOT_BIN.UPD.ABORT', zone, txn)
        raise
    else:
        if dryrun:
            conn.execute_command('KNOT_BIN.UPD.ABORT', zone, txn)
        else:
            if conn.execute_command('KNOT_BIN.UPD.DIFF', zone, txn):
                conn.execute_command('KNOT_BIN.UPD.COMMIT', zone, txn)
            else:
                conn.execute_command('KNOT_BIN.UPD.ABORT', zone, txn)

def store_zone_record(conn, zone, txn, record):
    resp = conn.execute_command('KNOT_BIN.ZONE.STORE', zone, txn,
                                record[0], record[1], record[2], record[3],
                                record[4], "M")
    if resp != b'OK':
        raise Exception("Failed to store record")

def resolve_zone_record(conn, stats, zone, txn, record):
    for dname in rdata_to_dname_list(record[4]):
        try:
            resp = getaddrinfo(dname, None, type=SOCK_DGRAM)
            for r in resp:
                new_record = record[0:1]
                if r[0] == AF_INET or r[0] == AF_INET6:
                    bin = inet_pton(r[0], r[4][0])
                    size = len(bin).to_bytes(2, byteorder='little', signed=False)
                    new_record.extend([af_to_rtype(r[0]), record[2], 1, size + bin])
                else:
                    continue

                store_zone_record(conn, zone, txn, new_record)
                if r[0] == AF_INET:
                    stats.ipv4 += 1
                else:
                    stats.ipv6 += 1
            stats.resolved += 1
        except (gaierror, UnicodeEncodeError): # Not found - skip
            stats.not_found += 1

def store_upd_record(conn, zone, txn, record):
    resp = conn.execute_command('KNOT_BIN.UPD.ADD', zone, txn,
                                record[0], record[1], record[2], record[3], record[4], "M")
    if resp != b'OK':
        raise Exception("Failed to insert record")

def remove_upd_record(conn, zone, txn, record):
    resp = conn.execute_command('KNOT_BIN.UPD.REM', zone, txn,
                                record[0], record[1], record[2], record[3], record[4])
    if resp != b'OK':
        raise Exception("Failed to delete record")

def resolve_upd_record(conn, stats, zone, txn, record):
    for dname in rdata_to_dname_list(record[4]):
        try:
            resp = getaddrinfo(dname, None, type=SOCK_DGRAM)
            for r in resp:
                new_record = record[0:1]
                if r[0] == AF_INET or r[0] == AF_INET6:
                    bin = inet_pton(r[0], r[4][0])
                    size = len(bin).to_bytes(2, byteorder='little', signed=False)
                    new_record.extend([af_to_rtype(r[0]), record[2], 1, size + bin])
                else:
                    continue
                store_upd_record(conn, zone, txn, new_record)
                if r[0] == AF_INET:
                    stats.ipv4 += 1
                else:
                    stats.ipv6 += 1
            stats.resolved += 1
        except (gaierror, UnicodeEncodeError): # Not found - skip
            stats.not_found += 1

def convert_zone_new(conn, stats, zone, input, output, dryrun):
    global stdout_lock

    input_resp = conn.execute_command('KNOT_BIN.ZONE.LOAD', zone, int_to_bytes(input))
    with knot_zone_transaction(conn, zone, output, dryrun) as txn:
        for r in input_resp:
            if r[1] == RRType.ALIAS:
                resolve_zone_record(conn, stats, zone, txn, r)
            else:
                store_zone_record(conn, zone, txn, r)
        if dryrun:
            zone_str = dname_to_str(zone)
            resp = conn.execute_command('KNOT.ZONE.LOAD', zone_str, txn_to_str(txn))
            stdout_lock.acquire()
            print(f'=== FULL {zone_str} ===')
            for record in resp:
                print(*[x.decode() for x in record], sep=' ')
            stdout_lock.release()

def convert_zone_existing(conn, stats, zone, input, output, dryrun):
    global stdout_lock

    input_resp = conn.execute_command('KNOT_BIN.ZONE.LOAD', zone, int_to_bytes(input))
    old_resp = conn.execute_command('KNOT_BIN.ZONE.LOAD', zone, int_to_bytes(output))
    with knot_upd_transaction(conn, zone, output, dryrun) as txn:
        for r in old_resp:
            if r[1] == RRType.SOA:
                current_soa = r
                continue
            remove_upd_record(conn, zone, txn, r)
        for r in input_resp:
            if r[1] == RRType.ALIAS:
                resolve_upd_record(conn, stats, zone, txn, r)
            else:
                if r[1] == RRType.SOA:
                    input_soa = r
                    continue
                store_upd_record(conn, zone, txn, r)
        if conn.execute_command('KNOT_BIN.UPD.DIFF', zone, txn):
            remove_upd_record(conn, zone, txn, current_soa)
            new_serial = (get_serial(current_soa[4]) + 1) % (2**32)
            input_soa[4] = set_serial(input_soa[4], new_serial)
            store_upd_record(conn, zone, txn, input_soa)

        if dryrun:
            zone_str = dname_to_str(zone)
            resp = conn.execute_command('KNOT.UPD.DIFF', zone_str, txn_to_str(txn))
            stdout_lock.acquire()
            print(f'=== UPDATE {zone_str} ===')
            for diff in resp:
                for rem in diff[0]:
                    print('- ', end='')
                    print(*[x.decode() for x in rem], sep=' ')
                for add in diff[1]:
                    print('+ ', end='')
                    print(*[x.decode() for x in add], sep=' ')
            stdout_lock.release()

def convert_zone(conf, zone):
    stats = Stats()

    zonename = zone[0]
    exists = zone[1]

    input = conf.input_instance
    output = conf.output_instance
    dryrun = conf.dry_run

    conn = Redis(
        host = conf.addr,
        port = conf.port,
        ssl = conf.tls,
        ssl_certfile = conf.tls_cert,
        ssl_keyfile = conf.tls_key,
        ssl_ca_certs = conf.tls_ca,
        ssl_cert_reqs = conf.tls_insecure,
        socket_timeout = 5,
    )

    if not exists:
        convert_zone_new(conn, stats, zonename, input, output, dryrun)
        stats.new += 1
    else:
        convert_zone_existing(conn, stats, zonename, input, output, dryrun)
        stats.updated += 1

    conn.close()

    return stats

def list_zones(conn, input, output):
    input_mask = 1 << (input - 1)
    output_mask = 1 << (output - 1)

    resp = conn.execute_command('KNOT_BIN.ZONE.LIST')
    filtered = filter(lambda x: (bytes_to_int(x[1]) & input_mask) != 0, resp)
    return map(lambda x: (x[0], (bytes_to_int(x[1]) & output_mask) != 0), filtered)

def main():
    stats = Stats()
    args = arg_parser()
    try:
        conf = args.parse_args()
        conn = Redis(
            host=conf.addr,
            port=conf.port,
            ssl=conf.tls,
            ssl_certfile=conf.tls_cert,
            ssl_keyfile=conf.tls_key,
            ssl_ca_certs=conf.tls_ca,
            ssl_cert_reqs=conf.tls_insecure,
            socket_timeout=5
        )

        executor = ProcessPoolExecutor()
        zones = list(list_zones(conn, conf.input_instance, conf.output_instance))
        conn.close()
        for s in executor.map(partial(convert_zone, conf), zones):
            stats += s
        executor.shutdown(wait=True)

        if conf.print_stats:
            print("Statistics\n----------")
            print(stats)
    except ConnectionError as e:
        err = sub(r'^Error\s+-?\d+\s+', 'Error: ', e.args[0])
        print(err, file=stderr)
        exit(1)
    except (ResponseError, TimeoutError) as e:
        print("Error: " + e.args[0], file=stderr)
        exit(1)
    except ArgumentError as e:
        print("Error: " + e.message, file=stderr)
        args.print_help()
        exit(1)
    except Exception as e:
        exit(1)

if __name__ == "__main__":
    main()
