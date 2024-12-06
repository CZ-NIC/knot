#!/usr/bin/env python3

import argparse
import http.server
import ipaddress
import psutil
import re
import socket
import subprocess

import libknot
import libknot.control

from prometheus_client.core import REGISTRY
from prometheus_client.core import CounterMetricFamily
from prometheus_client.core import GaugeMetricFamily
from prometheus_client.exposition import MetricsHandler


def memory_usage():
    out = dict()
    try:
        pids = subprocess.check_output(['pidof', 'knotd']).decode().split()
        for pid in pids:
            out[pid] = psutil.Process(int(pid)).memory_info()._asdict()['rss']
    finally:
        return out


class KnotCollector(object):
    def __init__(self, lib, sock, ttl,
            collect_meminfo : bool,
            collect_stats : bool,
            collect_zone_stats : bool,
            collect_zone_status : bool,
            collect_zone_timers : bool,
            collect_zone_serial : bool,):
        libknot.Knot(lib)
        self._sock = sock
        self._ttl = ttl
        self.collect_meminfo = collect_meminfo
        self.collect_stats = collect_stats
        self.collect_zone_stats = collect_zone_stats
        self.collect_zone_status = collect_zone_status
        self.collect_zone_timers = collect_zone_timers
        self.collect_zone_serial = collect_zone_serial

    def convert_state_time(time):
        if time.startswith(("pending", "running", "frozen")):
            return 0
        elif time == "not scheduled" or time == "-":
            return None
        else:
            match = re.match(r"([+-])((\d+)D)?((\d+)h)?((\d+)m)?((\d+)s)?", time)
            seconds = -1 if match.group(1) == '-' else 1
            if match.group(3):
                seconds = seconds + 86400 * int(match.group(3))
            if match.group(5):
                seconds = seconds + 3600 * int(match.group(5))
            if match.group(7):
                seconds = seconds + 60 * int(match.group(7))
            if match.group(9):
                seconds = seconds + int(match.group(9))

        return seconds

    def collect(self):
        ctl = libknot.control.KnotCtl()
        ctl.connect(self._sock)
        ctl.set_timeout(self._ttl)
        metric_families = dict()

        def metric_families_append(family, labels, labels_val, data):
            m = metric_families.get(family, GaugeMetricFamily(family, '', labels=labels))
            c = metric_families.get(family + '_total', CounterMetricFamily(family, '', labels=labels))
            m.add_metric(labels_val, data)
            c.add_metric(labels_val, data)
            metric_families[family] = m
            metric_families[family + '_total'] = c

        if self.collect_meminfo:
            # Get global metrics.
            for pid, usage in memory_usage().items():
                metric_families_append('knot_memory_usage', ['section', 'type'], ['server', str(pid)], usage)

        if self.collect_stats:
            ctl.send_block(cmd="stats", flags="")
            global_stats = ctl.receive_stats()

            for section, section_data in global_stats.items():
                for item, item_data in section_data.items():
                    name = ('knot_' + item).replace('-', '_')
                    try:
                        for kind, kind_data in item_data.items():
                            metric_families_append(name, ['section', 'type'], [section, kind], kind_data)

                    except AttributeError:
                        metric_families_append(name, ['section'], [section], item_data)

        if self.collect_zone_stats:
            # Get zone metrics.
            ctl.send_block(cmd="zone-stats", flags="")
            zone_stats = ctl.receive_stats()

            if "zone" in zone_stats:
                for zone, zone_data in zone_stats["zone"].items():
                    for section, section_data in zone_data.items():
                        for item, item_data in section_data.items():
                            name = ('knot_' + item).replace('-', '_')
                            try:
                                for kind, kind_data in item_data.items():
                                    metric_families_append(name, ['zone', 'section', 'type'], [zone, section, kind], kind_data)
                            except AttributeError:
                                metric_families_append(name, ['zone', 'section'], [zone, section], item_data)

        if self.collect_zone_status:
            # zone state metrics
            ctl.send_block(cmd="zone-status")
            zone_states = ctl.receive_block()

            for zone, info in zone_states.items():
                if self.collect_zone_serial:
                    serial = info.get('serial', False)
                    if serial and serial != "none" and serial != "-":
                        metric_families_append('knot_zone_serial', ['zone'], [zone], int(serial))

                metrics = ['expiration', 'refresh']

                for metric in metrics:
                    seconds = KnotCollector.convert_state_time(info[metric])
                    if seconds == None:
                        continue

                    metric_families_append('knot_zone_stats_' + metric, ['zone'], [zone], seconds)

        if self.collect_zone_timers:
            # zone configuration metrics
            ctl.send_block(cmd="zone-read", rtype="SOA")
            zones = ctl.receive_block()

            for name, params in zones.items():
                metrics = [
                    {"name": "knot_zone_refresh",    "index": 3},
                    {"name": "knot_zone_retry",      "index": 4},
                    {"name": "knot_zone_expiration", "index": 5},
                ]

                zone_config = params[name]['SOA']['data'][0].split(" ")

                for metric in metrics:
                    metric_families_append(metric['name'], ['zone'], [name], int(zone_config[metric['index']]))

        for val in metric_families.values():
            yield val


def main():
    parser = argparse.ArgumentParser(
        formatter_class = argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--web-listen-addr",
        default="127.0.0.1",
        help="address on which to expose metrics."
    )

    parser.add_argument(
        "--web-listen-port",
        type=int,
        default=9433,
        help="port on which to expose metrics."
    )

    parser.add_argument(
        "--knot-library-path",
        default=None,
        help="path to libknot."
    )

    parser.add_argument(
        "--knot-socket-path",
        default="/run/knot/knot.sock",
        help="path to knot control socket."
    )

    parser.add_argument(
        "--knot-socket-timeout",
        type=int,
        default=2000,
        help="timeout for Knot control socket operations."
    )

    parser.add_argument(
        "--no-meminfo",
        action='store_false',
        help="disable collection of memory usage"
    )

    parser.add_argument(
        "--no-global-stats",
        action='store_false',
        help="disable collection of global statistics"
    )

    parser.add_argument(
        "--no-zone-stats",
        action='store_false',
        help="disable collection of zone statistics"
    )

    parser.add_argument(
        "--no-zone-status",
        action='store_false',
        help="disable collection of zone status"
    )

    parser.add_argument(
        "--no-zone-serial",
        action='store_false',
        help="disable collection of zone serial"
    )

    parser.add_argument(
        "--zone-timers",
        action='store_true',
        default=False,
        help="enable collection of zone SOA timer values"
    )

    parser.add_argument(
        "--no-zone-timers",
        action='store_const',
        const=None,
        help="supported for compatibility reasons; no effect",
        # deprecated=True # in python >=3.13
    )

    args = parser.parse_args()

    REGISTRY.register(KnotCollector(
        args.knot_library_path,
        args.knot_socket_path,
        args.knot_socket_timeout,
        args.no_meminfo,
        args.no_global_stats,
        args.no_zone_stats,
        args.no_zone_status,
        args.zone_timers,
        args.no_zone_serial,
    ))

    class Server(http.server.HTTPServer):
        def __init__(self, server_address, RequestHandlerClass):
            ip = ipaddress.ip_address(server_address[0])
            self.address_family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
            super().__init__(server_address, RequestHandlerClass)

    httpd = Server(
        (args.web_listen_addr, args.web_listen_port),
        MetricsHandler,
    )

    httpd.serve_forever()


if __name__ == '__main__':
    main()
