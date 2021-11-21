#!/usr/bin/python3

# Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# requirements:
# sudo apt install libmysqlclient-dev
# pip3 install sqlobject configparser mysqlclient argparse

from sqlobject import *
import configparser
import argparse

import os
import string
import sys
import time
import re
from subprocess import DEVNULL, PIPE, Popen

# globals
connection = None
soa_serial = int(time.time())
config = configparser.ConfigParser()
fix_absolute = False
storage = os.getcwd()
knotc_binary = "knotc"
knotc_socket = None
slave_mode = False
conf_txn_open = False
knotc_zone_reload = []
knotc_timeout = 10

class Domains(SQLObject):
    # id = IntCol() # implicitly there
    name = StringCol()
    master = StringCol()
    last_check = IntCol()
    type = StringCol()
    notified_serial = IntCol()
    account = StringCol()

class Records(SQLObject):
    # id = IntCol() # implicitly there
    domain = ForeignKey('Domains')
    name = StringCol()
    type = StringCol()
    content = StringCol()
    ttl = IntCol()
    prio = IntCol()
    change_date = IntCol()
    ordername = StringCol()
    auth = IntCol()

class Changes(SQLObject):
    # id = IntCol() # implicitly there
    domain = ForeignKey('Domains')
    type = IntCol() # -1 .. zone removed; 0 .. zone modified; 1 .. zone added

def remove_dot(s):
    return s[:-1] if s[-1] == '.' else s

def fix_abs(name):
    return remove_dot(name) + '.' if fix_absolute else name

def domain_get_records(domain, txn):
    if str(domain).isdigit():
        return Records.select(Records.q.domain == domain, connection=txn)
    else:
        dn = remove_dot(domain)
        return Records.select(AND(Domains.q.id == Records.q.domain, Domains.q.name == dn), connection=txn)

def domain_id2name(domain, txn):
    return Domains.select(Domains.q.id == domain, connection=txn)[0].name

def get_config(key, default_val):
    global config
    return int(config['DEFAULT'][key]) if key in config['DEFAULT'] and config['DEFAULT'][key] is not None else default_val

def get_soa_params():
    refresh = get_config("soa-refresh-default", 10800)
    retry = get_config("soa-retry-default", 3600)
    expire = get_config("soa-expire-default", 604800)
    minttl = get_config("soa-minimum-ttl", 3600)
    return (refresh, retry, expire, minttl)

def soa_content(db_content):
    global soa_serial

    (nameserver, contact, fake_serial) = db_content.split()
    ns = fix_abs(nameserver)
    co = fix_abs(contact.replace("@", "."))

    (refresh, retry, expire, minttl) = get_soa_params()
    return ("%s %s %d %d %d %d %d" % (ns, co, soa_serial, refresh, retry, expire, minttl))

def zone_storage(zone):
    global storage
    return os.path.join(storage, "%s.zone" % remove_dot(zone))

def knotc_single(*args):
    global knotc_binary
    global knotc_socket
    global knotc_timeout

    cmd = [ knotc_binary, "-s", knotc_socket, "-t", str(knotc_timeout) ] + list(args)
    p = Popen(cmd, stdout=PIPE, stderr=PIPE, universal_newlines=True)
    (stdout, stderr) = p.communicate()
    if p.returncode != 0:
        raise Exception("error: knotc %s failed: '%s'" % (str(args), stderr))

def zone_template(zone):
    # this function is intended to be patched by user's business logic
    return None

# param type:
#   -1 ... remove this zone
#    0 ... mark this zone as modified (fallback to 2 if not exists)
#    1 ... add zone (fallback to 0 if exists already)
#    2 ... add zone no fallback (ignore if exists already)
def knotc_send(type, zone):
    global slave_mode
    global conf_txn_open
    global knotc_zone_reload
    if type == 0:
        try:
            # ensure by zone-status that the zone exists
            knotc_single("zone-status", zone)

            knotc_zone_reload.append(zone)
        except:
            knotc_send(2, zone)
    else:
        try:
            if not conf_txn_open:
                knotc_single("conf-begin")
                conf_txn_open = True
            if type > 0:
                try:
                    knotc_single("conf-set", "zone[%s]" % zone)
                    knotc_single("conf-set", "zone[%s].file" % zone, zone_storage(zone))
                    template = zone_template(remove_dot(zone))
                    if template is not None:
                        knotc_single("conf-set", "zone[%s].template" % zone, template)
                except:
                    if type > 1:
                        pass
                    else:
                        knotc_send(0, zone)
            else:
                knotc_single("conf-unset", "zone[%s]" % zone)
                try:
                    knotc_zone_reload.remove(zone)
                except:
                    pass
        except:
            knotc_single("conf-abort")
            conf_txn_open = False
            raise

def print_record(record, outfile):
    t = record.type.upper()
    if t == 'SOA':
        content = soa_content(record.content)
    elif t == 'MX' or t == 'SRV':
        content = "%d %s" % (record.prio, record.content)
    elif t == 'TXT' or t == 'SPF':
        content = "\"%s\"" % record.content
    else:
        content = record.content

    if t in ('NS', 'MX', 'CNAME', 'DNAME', 'SRV', 'PTR'):
        content = fix_abs(content)

    record = ("%s. %d %s %s\n" % (record.name, record.ttl, t, content))
    outfile.write(record)

def print_domain(domain, change_type = 0, txn = None):
    global knotc_socket
    global slave_mode
    dn = domain_id2name(domain, txn) if str(domain).isdigit() else domain
    if not slave_mode:
        file_name = zone_storage(dn)
        tmp_name = "%s.tmp" % file_name
        f = open(tmp_name, "w")
        for r in domain_get_records(domain, txn):
            print_record(r, f)
        f.close()
        os.rename(tmp_name, file_name)
    if knotc_socket is not None:
        knotc_send(change_type, dn)
    print("Updated zone %s" % dn)

def domain_from_change(change, txn):
    global knotc_socket
    if change.type >= 0:
        print_domain(change.domain.name, change.type, txn)
    else:
        dn = change.domain.name
        try:
            os.remove(zone_storage(dn))
        except:
            print("Warning: failed to delete zonefile for %s" % dn, file=sys.stderr)
        if knotc_socket is not None:
            knotc_send(change.type, dn)
        else:
            print("Warning: removed zone '%s', but unspecified knotc socket." % dn, file=sys.stderr)

def process_changes(startwith):
    global connection
    processed = []
    try:
        txn = connection.transaction()
        for ch in Changes.select(Changes.q.id > startwith, connection=txn):
            domain_from_change(ch, txn)
            processed.append(ch.id)
        txn.commit()
    finally:
        if len(processed) > 0:
            print("Processed up to change_id %d" % processed[-1])

def process_all():
    global connection
    txn = connection.transaction()
    for d in Domains.select(connection=txn):
        print_domain(d.id, txn = txn)
    txn.commit()

def read_config_file(filename):
    global config

    with open(filename, 'r') as f:
        fcontent = '[DEFAULT]\n' + f.read()

    config.read_string(fcontent)

def main():
    global storage
    global knotc_socket
    global soa_serial
    global fix_absolute
    global connection
    global slave_mode
    global conf_txn_open
    global knotc_zone_reload
    global knotc_timeout

    argp = argparse.ArgumentParser(prog='dns_sql2zf', description="Export DNS records from Mysql or Postgres DB into zonefile.", epilog="(C) CZ.NIC, GPLv3")
    argp.add_argument(dest='domains', metavar='zone', nargs='*', help='Zone to be exported.')
    argp.add_argument('--db', dest='dburi', metavar='DB_URI', nargs=1, required=True, help='URI of database to export from (example: mysql://user:password@127.0.0.1/powerdns_db).')
    argp.add_argument('--storage', dest='storage', metavar='path', nargs=1, help='Storage for the generated zonefile (otherwise current dir).')
    argp.add_argument('--all', dest='all', action='store_true', help="Export all zones.")
    argp.add_argument('--confile', dest='confile', metavar='file', nargs=1, help='PowerDNS configfile to obtain SOA parameters (otherwise defaults).')
    argp.add_argument('--serial', dest='soa_serial', type=int, metavar='uint32', nargs=1, help='SOA serial number (otherwise UNIX timestamp).')
    argp.add_argument('--absolute-names', dest='fix_absolute', action='store_true', help="Interpret names in records' contents (e.g. CNAME, NS...) as absolute even if w/o trailing dot.")
    argp.add_argument('--from-changes', dest='from_changes', metavar="from_id", nargs='?', const=0, help="Export zones listed in extra 'changes' table.")
    argp.add_argument('--knotc', dest='knotc_socket', metavar='knot_socket', nargs=1, help="Notify Knot DNS about changes (requires: $PATH/knotc).")
    argp.add_argument('--knotc-timeout', dest='knotc_timeout', type=int, metavar='uint32', nargs=1, help='Timeout for knotc commands (default 10).')
    argp.add_argument('--slave', dest='slave', action='store_true', help="Don't generate zonefiles, use 'knotc zone-refresh' instead of zone-reload.")
    argp.add_argument('--version', action='version', version='dns_sql2zf 0.1')
    args = argp.parse_args()

    if args.soa_serial is not None:
        soa_serial = args.soa_serial[0]

    if args.confile is not None:
        read_config_file(args.confile[0])

    if args.storage is not None:
        storage = args.storage[0]

    if args.fix_absolute:
        fix_absolute = True

    if args.knotc_socket is not None:
        knotc_socket = args.knotc_socket[0]

    if args.knotc_timeout is not None:
        knotc_timeout = args.knotc_timeout[0]

    if args.slave:
        slave_mode = True

    connection = connectionForURI(args.dburi[0])
    sqlhub.processConnection = connection

    for domain in args.domains:
        print_domain(domain)

    if args.all:
        process_all()

    if args.from_changes is not None:
        process_changes(args.from_changes)

    if conf_txn_open:
        knotc_single("conf-commit")

    for zone in knotc_zone_reload:
        knotc_single("zone-reload" if not slave_mode else "zone-refresh", zone)

if __name__ == "__main__":
    main()

