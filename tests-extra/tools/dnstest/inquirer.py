#!/usr/bin/env python3

import time
import random
import multiprocessing
import dns.message
import dns.query
import dnstest.server

class Inquirer:

    def __init__(self):
        self.proc = None
        self.active = False

    def start(self, *args):
        self.proc = multiprocessing.Process(target=self._query, args=args)
        self.active = True
        self.proc.start()

    # queries=list(list(name, type),...)
    def _query(self, server, queries=None, sleep=0.05):
        _udp = random.choice([True, False])
        _queries = list()

        if queries:
            for q in queries:
                query = dns.message.make_query(q[0], q[1], "IN")
                query.want_dnssec()
                _queries.append(query)
        else:
            for z in random.sample(list(server.zones), min(len(server.zones), 2)):
                query = dns.message.make_query(z, "SOA", "IN")
                query.want_dnssec()
                _queries.append(query)

        while self.active:
            try:
                for q in _queries:
                    if _udp:
                        dns.query.udp(q, server.addr, port=server.port,
                                      timeout=0.02)
                    else:
                        dns.query.tcp(q, server.addr, port=server.port,
                                      timeout=0.05)
            except:
                pass

            time.sleep(sleep)

    def stop(self):
        self.active = False
        if self.proc:
            self.proc.terminate()
            self.proc = None
