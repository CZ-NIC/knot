#!/usr/bin/env python3

import os
import random
import shutil
import socket
import time
import dns.zone
import zone_generate
from dnstest.utils import *
import dnstest.params as params
import dnstest.server
import dnstest.keys
import dnstest.zonefile

class Test(object):
    '''Specification of DNS test topology'''

    MAX_START_TRIES = 10
    LOCAL_ADDR = {4: "127.0.0.1", 6: "::1"}

    # Value of the last generated port.
    last_port = None

    # Number of unsuccessful starts of servers. Recursion protection.
    start_tries = 0

    def __init__(self, ip=None, tsig=None):
        if not os.path.exists(params.out_dir):
            raise Exception("Output directory doesn't exist")

        self.out_dir = params.out_dir
        self.data_dir = params.test_dir + "/data/"
        self.zones_dir = self.out_dir + "/zones/"

        self.ip = ip if ip else random.choice([4, 6])
        if self.ip not in [4, 6]:
            raise Exception("Invalid IP version")

        self.tsig = bool(tsig) if tsig != None else random.choice([True, False])

        self.servers = set()

        dnstest.server.Knot.count = 0
        dnstest.server.Bind.count = 0
        dnstest.server.Nsd.count = 0
        dnstest.server.Dummy.count = 0

    def _check_port(self, port):
        if not port:
            return False

        proto = socket.AF_INET if self.ip == 4 else socket.AF_INET6

        try:
            s = socket.socket(proto, socket.SOCK_DGRAM)
            s.bind((Test.LOCAL_ADDR[self.ip], port))
            s.close
            s = socket.socket(proto, socket.SOCK_STREAM)
            s.bind((Test.LOCAL_ADDR[self.ip], port))
            s.close
        except:
            return False

        return True

    def _gen_port(self):
        min_port = 10000
        max_port = 50000

        port = Test.last_port
        if port:
            port = port + 1 if port < max_port else min_port

        while not self._check_port(port):
            port = random.randint(min_port, max_port)

        Test.last_port = port
        return port

    def server(self, server, nsid=None, ident=None, version=None, \
               valgrind=None):
        if server == "knot":
            srv = dnstest.server.Knot()
        elif server == "bind":
            srv = dnstest.server.Bind()
        elif server == "nsd":
            srv = dnstest.server.Nsd()
        elif server == "dummy":
            srv = dnstest.server.Dummy()
        else:
            raise Exception("Usupported server %s" % server)

        type(srv).count += 1

        if params.valgrind_bin and \
           (valgrind or (valgrind == None and server == "knot")):
            srv.valgrind = [params.valgrind_bin, params.valgrind_flags]

        srv.data_dir = self.data_dir

        srv.nsid = nsid
        srv.ident = ident
        srv.version = version

        srv.ip = self.ip
        srv.addr = Test.LOCAL_ADDR[self.ip]
        srv.tsig = dnstest.keys.Tsig() if self.tsig else None

        srv.name = "%s%s" % (server, srv.count)
        srv.dir = self.out_dir + "/" + srv.name
        srv.fout = srv.dir + "/stdout"
        srv.ferr = srv.dir + "/stderr"
        srv.confile = srv.dir + "/%s.conf" % srv.name

        try:
            os.mkdir(srv.dir)
        except:
            raise Exception("Can't create directory %s" % srv.dir)

        if srv.ctlkey:
            srv.ctlkeyfile = srv.dir + "/%s.ctlkey" % srv.name
            srv.ctlkey.dump(srv.ctlkeyfile)

        self.servers.add(srv)
        return srv

    def _generate_conf(self):
        # Next two loops can't be merged!
        for server in self.servers:
            server.port = self._gen_port()
            server.ctlport = self._gen_port()

        for server in self.servers:
            server.gen_confile()

    def start(self):
        '''Start all test servers'''

        if self.start_tries > Test.MAX_START_TRIES:
            raise Exception("Can't start all servers")

        self.start_tries += 1

        self._generate_conf()

        def srv_sort(server):
            masters = 0
            for z in server.zones:
                if server.zones[z].master: masters += 1
            return masters

        # Sort server list by number of masters. I.e. masters are prefered.
        for server in sorted(self.servers, key=srv_sort):
            server.start()
            if not server.running():
                self.stop()
                self.start()

        params.test = self
        self.start_tries = 0

    def stop(self):
        '''Stop all servers'''

        for server in self.servers:
            server.stop()
        params.test = None

    def end(self):
        '''Finish testing'''

        self.stop()
        for server in self.servers:
            server._valgrind_check()

    def sleep(self, seconds):
        time.sleep(seconds)

    def zone(self, name, file_name=None, local=False, dnssec=None, serial=None,
             exists=True):

        zone = dnstest.zonefile.ZoneFile(self.zones_dir)
        zone.set_name(name)

        if local:
            src_dir = self.data_dir
        else:
            src_dir = params.common_data_dir

        zone.set_file(file_name=file_name, storage=src_dir, dnssec=dnssec,
                      exists=exists)

        return [zone]

    def zone_rnd(self, number, dnssec=None, records=None, serial=None):
        zones = list()

        # Generate unique zone names.
        names = zone_generate.main(["-n", number]).split()
        for name in names:
            zone = dnstest.zonefile.ZoneFile(self.zones_dir)
            zone.set_name(name)
            zone.gen_file(dnssec=dnssec, records=records, serial=serial)
            zones.append(zone)

        return zones

    def link(self, zones, master, slave=None, ddns=False):
        for zone in zones:
            if master not in self.servers:
                raise Exception("Server is out of testing scope")
            master.set_master(zone, slave, ddns)

            if slave:
                if slave not in self.servers:
                    raise Exception("Server is out of testing scope")
                slave.set_slave(zone, master, ddns)

    def xfr_diff(self, server1, server2, zones):
        check_log("CHECK AXFR DIFF")
        for zone in zones:
            detail_log("Zone %s %s-%s:" % (zone.name, server1.name, server2.name))
            z1 = dns.zone.from_xfr(server1.dig(zone.name, "AXFR").resp)
            z2 = dns.zone.from_xfr(server2.dig(zone.name, "AXFR").resp)

            z1_keys = set(z1.nodes.keys())
            z2_keys = set(z2.nodes.keys())

            z1_diff = sorted(list(z1_keys - z2_keys))
            z2_diff = sorted(list(z2_keys - z1_keys))
            z_keys = sorted(list(z1_keys & z2_keys))

            if z1_diff:
                set_err("XFR DIFF")
                detail_log("Extra records in %s:" % server1.name, True)
                for key in z1_diff:
                    for record in z1.nodes[key]:
                        detail_log("  %s %s" % (key, str(record)), True)

            if z2_diff:
                set_err("XFR DIFF")
                detail_log("Extra records in %s:" % server2.name, True)
                for key in z2_diff:
                    for record in z2.nodes[key]:
                        detail_log("  %s %s" % (key, str(record)), True)

            if not z_keys:
                return

            for key in z_keys:
                if z1.nodes[key] != z2.nodes[key]:
                    set_err("XFR DIFF")
                    detail_log("Different nodes:", True)
                    detail_log("%s:" % server1.name, True)
                    for record in z1.nodes[key]:
                        detail_log("  " + str(record), True)
                    detail_log("%s:" % server2.name, True)
                    for record in z2.nodes[key]:
                        detail_log("  " + str(record), True)

            detail_log(SEP)
