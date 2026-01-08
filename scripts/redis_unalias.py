#!/usr/bin/env python3
# Copyright (C) CZ.NIC, z.s.p.o. and contributors
# SPDX-License-Identifier: GPL-2.0-or-later
# For more information, see <https://www.knot-dns.cz/>

"""Script for resolving ALIAS records in zones stored in Redis using local resolver."""

# requirements redis[hiredis]
from argparse import ArgumentError, ArgumentParser
from contextlib import contextmanager
from enum import IntEnum
from re import sub
from redis import Redis
from redis.exceptions import ConnectionError, ResponseError, TimeoutError
from socket import AF_INET, AF_INET6, SOCK_DGRAM, gaierror, getaddrinfo, inet_pton
from sys import exit, stderr

class RRType(IntEnum):
    A = 1
    AAAA = 28
    ALIAS = 65401

class Stats:
    new = 0
    updated = 0
    resolved = 0
    created = 0
    not_found = 0

    def __str__(self):
        return \
            f'zones:   {self.new + self.updated}\t[new: {self.new}, updated: {self.updated}]\n' + \
            f'aliases: {self.resolved + self.not_found}\t[resolved: {self.resolved}, created: {self.created}, not found: {self.not_found}]\n'


def arg_parser():
    parser = ArgumentParser(
                    exit_on_error=False,
                    prog='redis-unalias.py',
                    description='Knot Redis ALIAS job',
                    epilog='Once started it converts ALIAS records in one instance (every zone in DB) into other instance')
    parser.add_argument('input_instance',       type=int,                                               help='instance that converts ALIAS from')
    parser.add_argument('output_instance',      type=int,                                               help='instance that converts ALIAS to')
    parser.add_argument('-a', '--addr',         type=str, nargs='?', default='localhost',               help='redis-server address')
    parser.add_argument('-p', '--port',         type=int, nargs='?', default=6379,                      help='redis-server port')
    parser.add_argument('-C', '--tls_cert',     type=str, nargs='?', default=None,                      help='client cert for redis-server connection')
    parser.add_argument('-K', '--tls_key',      type=str, nargs='?', default=None,                      help='client key for redis-server connection')
    parser.add_argument('-A', '--tls_ca',       type=str, nargs='?', default=None,                      help='client CA for redis-server connection')
    parser.add_argument('-t', '--tls',          default=False,      action='store_true',                help='use transport layer security (TLS)')
    parser.add_argument('-i', '--tls_insecure', default='required', action='store_const', const='none', help='disable client TLS validation')
    parser.add_argument('-d', '--dry_run',      default=False,      action='store_true',                help='print transaction instead of storing into Redis database')
    parser.add_argument('-s', '--print-stats',  default=False,      action='store_true',                help='print stats at the end of script run')
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
            resp = conn.execute_command('KNOT.ZONE.LOAD', dname_to_str(zone), txn_to_str(txn))
            conn.execute_command('KNOT_BIN.ZONE.ABORT', zone, txn)
            print(f'=== FULL {resp[0][0].decode()} ===')
            for record in resp:
                print(*[x.decode() for x in record], sep=' ')
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
            resp = conn.execute_command('KNOT.UPD.DIFF', dname_to_str(zone), txn_to_str(txn))
            conn.execute_command('KNOT_BIN.UPD.ABORT', zone, txn)
            print(f'=== UPDATE {resp[0][0][0][0].decode()} ===')
            for diff in resp:
                for rem in diff[0]:
                    print('- ', end='')
                    print(*[x.decode() for x in rem], sep=' ')
                for add in diff[1]:
                    print('+ ', end='')
                    print(*[x.decode() for x in add], sep=' ')
        else:
            conn.execute_command('KNOT_BIN.UPD.COMMIT', zone, txn)

def list_zones(conn, input, output):
    input_mask = 1 << (input - 1)
    output_mask = 1 << (output - 1)

    resp = conn.execute_command('KNOT_BIN.ZONE.LIST')
    filtered = filter(lambda x: (bytes_to_int(x[1]) & input_mask) != 0, resp)
    return map(lambda x: (x[0], (bytes_to_int(x[1]) & output_mask) != 0), filtered)

def convert_zone(conn, zone, input, output, dryrun):
    global stats
    if not zone[1]:
        convert_zone_new(conn, zone[0], input, output, dryrun)
        stats.new += 1
    else:
        convert_zone_existing(conn, zone[0], input, output, dryrun)
        stats.updated += 1

def convert_zone_new(conn, zone, input, output, dryrun):
    resp = conn.execute_command('KNOT_BIN.ZONE.LOAD', zone, int_to_bytes(input))
    with knot_zone_transaction(conn, zone, output, dryrun) as txn:
        for r in resp:
            if r[1] == RRType.ALIAS:
                resolve_zone_record(conn, zone, txn, r)
            else:
                store_zone_record(conn, zone, txn, r)

def resolve_zone_record(conn, zone, txn, record):
    global stats
    for dname in record_to_str_list(record[4]):
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
                stats.created += 1
            stats.resolved += 1
        except (gaierror, UnicodeEncodeError): # Not found - skip
            stats.not_found += 1

def af_to_rtype(af):
    if af == AF_INET:
        return RRType.A.value
    elif af == AF_INET6:
        return RRType.AAAA.value
    else:
        raise Exception('Unsupported type')

def record_to_str_list(dname):
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

def store_zone_record(conn, zone, txn, record):
    resp = conn.execute_command('KNOT_BIN.ZONE.STORE', zone, txn, record[0], record[1], record[2], record[3], record[4], "M")
    if resp != b'OK':
        raise Exception("Error while store")

def convert_zone_existing(conn, zone, input, output, dryrun):
    in_serial = conn.execute_command('KNOT_BIN.ZONE.EXISTS', zone, int_to_bytes(input))
    out_serial = conn.execute_command('KNOT_BIN.ZONE.EXISTS', zone, int_to_bytes(output))
    if (in_serial == out_serial):
        return
    old_zone_resp = conn.execute_command('KNOT_BIN.ZONE.LOAD', zone, int_to_bytes(output))
    input_zone_resp = conn.execute_command('KNOT_BIN.ZONE.LOAD', zone, int_to_bytes(input))
    with knot_upd_transaction(conn, zone, output, dryrun) as txn:
        for r in old_zone_resp:
            conn.execute_command('KNOT_BIN.UPD.REM', zone, txn, r[0], r[1], r[2], r[3], r[4])
        for r in input_zone_resp:
            if r[1] == RRType.ALIAS:
                resolve_upd_record(conn, zone, txn, r)
            else:
                store_upd_record(conn, zone, txn, r)

def resolve_upd_record(conn, zone, txn, record):
    global stats
    for dname in record_to_str_list(record[4]):
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
                stats.created += 1
            stats.resolved += 1
        except (gaierror, UnicodeEncodeError): # Not found - skip
            stats.not_found += 1

def store_upd_record(conn, zone, txn, record):
    resp = conn.execute_command('KNOT_BIN.UPD.ADD', zone, txn, record[0], record[1], record[2], record[3], record[4], "M")
    if resp != b'OK':
        raise Exception("Error while store")

def main():
    global stats
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
        for zone in list_zones(conn, conf.input_instance, conf.output_instance):
            convert_zone(conn, zone, conf.input_instance, conf.output_instance, conf.dry_run)
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

    if conf.print_stats:
        print("Stats:")
        print(stats)

if __name__ == "__main__":
    main()
