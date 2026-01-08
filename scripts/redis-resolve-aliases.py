#!/usr/bin/env python3

# requirements redis[hiredis]

from contextlib import contextmanager
from socket import AF_INET, AF_INET6, SOCK_RAW, gaierror, getaddrinfo

import argparse
import redis

def parse_args():
    parser = argparse.ArgumentParser(
                    prog='redis-resolve-aliases.py',
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
    return parser.parse_args()

@contextmanager
def knot_zone_transaction(conn, zone, inst):
    try:
        txn = conn.execute_command('KNOT.ZONE.BEGIN', zone, inst)
        yield txn
    except:
        conn.execute_command('KNOT.ZONE.ABORT', zone, txn)
        raise
    else:
        conn.execute_command('KNOT.ZONE.COMMIT', zone, txn)

def parse_zone_list(line):
    p = line.split(": ")
    zone = p[0]
    instances = p[1].split(", ")
    return (zone, instances)

def list_zones(conn, instance):
    resp = conn.execute_command('KNOT.ZONE.LIST', "--instances")
    parsed = map(parse_zone_list, resp)
    filtered_by_inst = filter(lambda l: str(instance) in l[1], parsed)
    return [ i[0] for i in filtered_by_inst ]

def convert_zone(conn, zone, input, output):
    resp = conn.execute_command('KNOT.ZONE.LOAD', zone, input)
    with knot_zone_transaction(conn, zone, output) as txn:
        for r in resp:
            if r[2] == "CNAME": # TODO replace CNAME with ALIAS
                resolve_record(conn, zone, txn, r)
            else:
                store_record(conn, zone, txn, r)

def resolve_record(conn, zone, txn, record):
    try:
        resp = getaddrinfo(record[3], None, type=SOCK_RAW)
        for r in resp:
            new_record = record[0:2]

            if r[0] == AF_INET:
                new_record.extend(['A', r[4][0]])
            elif r[0] == AF_INET6:
                new_record.extend(['AAAA', r[4][0]]) # TODO r[4] is tuple - could store something important
            else:
                continue

            store_record(conn, zone, txn, new_record)
    except gaierror: # Skip
        return

def store_record(conn, zone, txn, record):
    resp = conn.execute_command('KNOT.ZONE.STORE', zone, txn, " ".join(record))
    if resp != 'OK':
        raise Exception("Error while store")

def main():
    conf = parse_args()
    conn = redis.Redis(
        host=conf.addr,
        port=conf.port,
        ssl=conf.tls,
        ssl_certfile=conf.tls_cert,
        ssl_keyfile=conf.tls_key,
        ssl_ca_certs=conf.tls_ca,
        ssl_cert_reqs=conf.tls_insecure,
        decode_responses=True
    )
    # conn.ping() # TODO test connection ??
    for zone in list_zones(conn, conf.input_instance):
        convert_zone(conn, zone, conf.input_instance, conf.output_instance)

if __name__ == "__main__":
    main()