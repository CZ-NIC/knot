#!/usr/bin/env python3

import random
import threading
import dns.message
import dns.query
import dnstest.server

class Inquirer:

    def __init__(self):
        self._stop = None
        self.t = None

    def start(self, *args):
        self._stop = threading.Event()
        self.t = threading.Thread(target=self._query, args=args)
        self.t.start()

    def _query(self, server, timeout=0.05):
        _zones = random.sample(list(server.zones), min(len(server.zones), 2))
        _queries = list()
        _udp = random.choice([True, False])

        for z in _zones:
            _queries.append(dns.message.make_query(z, "SOA", "IN"))

        while not self._stop.is_set():
            try:
                for q in _queries:
                    if _udp:
                        dns.query.udp(q, server.addr, port=server.port,
                                      timeout=timeout)
                    else:
                        dns.query.tcp(q, server.addr, port=server.port,
                                      timeout=timeout)
            except:
                pass

    def stop(self):
        if self._stop:
            self._stop.set()
