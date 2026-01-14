#!/usr/bin/env python3
# Copyright (C) CZ.NIC, z.s.p.o. and contributors
# SPDX-License-Identifier: GPL-2.0-or-later
# For more information, see <https://www.knot-dns.cz/>

"""A simple Knot DNS probe client."""

import argparse
import datetime
import json
import libknot
import libknot.probe
import sys


def extract_dns_header(probe, fieldname):
    val = getattr(probe, fieldname)
    return {
        "additionals": val.additionals,
        "answers": val.answers,
        "authorities": val.authorities,
        "flag_aa": val.flag_aa,
        "flag_ad": val.flag_ad,
        "flag_cd": val.flag_cd,
        "flag_qr": val.flag_qr,
        "flag_ra": val.flag_ra,
        "flag_rd": val.flag_rd,
        "flag_tc": val.flag_tc,
        "flag_z": val.flag_z,
        "id": val.id,
        "opcode": val.opcode,
        "questions": val.questions,
        "rcode": val.rcode,
    }


def extract_addr(probe, fieldname):
    val = getattr(probe, fieldname)
    return probe.addr_str(val)


def extract_safe(probe, fieldname):
    convert_func = getattr
    try:
        convert_func = {
            "local_addr": extract_addr,
            "remote_addr": extract_addr,
            "query_hdr": extract_dns_header,
            "reply_hdr": extract_dns_header,
            "query_name": lambda probe, _: probe.qname_str(),
        }[fieldname]
    except KeyError:
        pass

    return convert_func(probe, fieldname)


def convert_json(probe):
    probe_as_dict = {}
    for field in probe._fields_:
        fieldname = field[0]
        fieldtype = field[1]
        fieldlen = field[2] if len(field) > 2 else None

        probe_as_dict[fieldname] = extract_safe(probe, fieldname)
    return probe_as_dict


def probe_loop(args):
    try:
        libknot.Knot(args.libknot_path)
    except:
        print("Cannot find shared library libknot.so")
        sys.exit(1)

    probe = libknot.probe.KnotProbe(args.probe_dir, args.channel)
    data = libknot.probe.KnotProbeDataArray(8)

    try:
        while True:
            if probe.consume(data, 1000) > 0:
                for item in data:
                    if args.json:
                        item_json = convert_json(item)
                        if not args.no_timestamp:
                            item_json["timestamp"] = datetime.datetime.now().isoformat()
                        log = json.dumps(item_json)
                    else:
                        log = item.str(color=not args.no_color, timestamp=not args.no_timestamp)
                    print(log)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class = argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-l", "--libknot-path",
        help="path to the libknot shared library"
    )
    parser.add_argument(
        "-d", "--probe-dir",
        default="/run/knot",
        help="path to the probe directory"
    )
    parser.add_argument(
        "-c", "--channel",
        type=int,
        default=1,
        help="the probe channel"
    )
    parser.add_argument(
        "--json",
        action='store_true',
        help="Print JSON formatted"
    )
    parser.add_argument(
        "--no-color",
        action='store_true',
        help="don't colorize the output (JSON is never colorized)"
    )
    parser.add_argument(
        "--no-timestamp",
        action='store_true',
        help="don't print the current timestamp"
    )
    args = parser.parse_args()

    probe_loop(args)
