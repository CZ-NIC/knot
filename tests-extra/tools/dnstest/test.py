#!/usr/bin/env python3

import ipaddress
import os
import random
import shutil
import socket
import time
import dns.name
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

    rel_time = time.time()

    def __init__(self, address=None, tsig=None, stress=True):
        if not os.path.exists(params.out_dir):
            raise Exception("Output directory doesn't exist")

        self.out_dir = params.out_dir
        self.data_dir = params.test_dir + "/data/"
        self.zones_dir = self.out_dir + "/zones/"

        if address == 4 or address == 6:
            self.addr = Test.LOCAL_ADDR[address]
        elif address:
            self.addr = address
        else:
            self.addr = Test.LOCAL_ADDR[random.choice([4, 6])]

        self.tsig = None
        if tsig != None:
            if type(tsig) is dnstest.keys.Tsig:
                self.tsig = tsig
            elif tsig:
                self.tsig = dnstest.keys.Tsig()
        elif random.choice([True, False]):
            self.tsig = dnstest.keys.Tsig()

        self.stress = stress

        self.servers = set()

        dnstest.server.Knot.count = 0
        dnstest.server.Bind.count = 0
        dnstest.server.Nsd.count = 0
        dnstest.server.Dummy.count = 0

        params.test = self

    def _check_port(self, port):
        if not port:
            return False

        family = socket.AF_INET
        if ipaddress.ip_address(self.addr).version == 6:
            family = socket.AF_INET6

        try:
            for stype in [socket.SOCK_DGRAM, socket.SOCK_STREAM]:
                s = socket.socket(family, stype)
                s.bind((self.addr, port))
                s.close()
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

    @property
    def hostname(self):
        hostname = socket.gethostname()
        addrinfo = socket.getaddrinfo(hostname, 0, socket.AF_UNSPEC,
                                      socket.SOCK_DGRAM, 0, socket.AI_CANONNAME)
        return addrinfo[0][3] if addrinfo else hostname

    def server(self, server, nsid=None, ident=None, version=None, \
               valgrind=None, address=None, port=None, ctlport=None, \
               external=False, tsig=None):
        if server == "knot":
            srv = dnstest.server.Knot()
        elif server == "bind":
            srv = dnstest.server.Bind()
        elif server == "nsd":
            srv = dnstest.server.Nsd()
        elif server == "dummy":
            srv = dnstest.server.Dummy()
        else:
            raise Failed("Unsupported server '%s'" % server)

        type(srv).count += 1

        srv.data_dir = self.data_dir

        srv.nsid = nsid
        srv.ident = ident
        srv.version = version

        if address == 4 or address == 6:
            srv.addr = Test.LOCAL_ADDR[address]
        elif address:
            srv.addr = address
        else:
            srv.addr = self.addr

        if port:
            srv.port = int(port)
            srv.fixed_port = True
            if not ctlport and server == "bind":
                raise Failed("Missing remote control port '%s'" % server)

        if ctlport:
            srv.ctlport = int(ctlport)

        if external:
            srv.external = True

        if self.tsig and not tsig:
            srv.tsig = dnstest.keys.Tsig()
        else:
            srv.tsig = tsig

        srv.tsig_test = self.tsig

        srv.name = "%s%s" % (server, srv.count)
        srv.dir = self.out_dir + "/" + srv.name
        srv.fout = srv.dir + "/stdout"
        srv.ferr = srv.dir + "/stderr"
        srv.valgrind_log = srv.dir + "/valgrind"
        srv.confile = srv.dir + "/%s.conf" % srv.name

        prepare_dir(srv.dir)

        if srv.ctlkey:
            srv.ctlkeyfile = srv.dir + "/%s.ctlkey" % srv.name
            srv.ctlkey.dump(srv.ctlkeyfile)

        if params.valgrind_bin and \
           (valgrind or (valgrind == None and server == "knot")):
            srv.valgrind = [params.valgrind_bin] + \
                           params.valgrind_flags.split() + \
                           ["--log-file=%s" % srv.valgrind_log]
            suppressions_file = "%s/%s.supp" % (params.common_data_dir, server)
            if os.path.isfile(suppressions_file):
                srv.valgrind.append("--suppressions=%s" % suppressions_file)

        self.servers.add(srv)
        return srv

    def server_remove(self, server=None):
        # Remove server/servers from the test.

        if server:
            if server.listening():
                server.stop()
            self.servers.discard(server)
            return

        servers = [srv for srv in self.servers]
        for server in servers:
            self.server_remove(server)

    def generate_conf(self):
        # Next two loops can't be merged!
        for server in self.servers:
            if server.fixed_port:
                continue

            server.port = self._gen_port()
            server.ctlport = self._gen_port()

        for server in self.servers:
            server.gen_confile()

    def start(self):
        '''Start all test servers'''

        if self.start_tries > Test.MAX_START_TRIES:
            raise Failed("Can't start all servers")

        self.start_tries += 1

        self.generate_conf()

        def srv_sort(server):
            masters = 0
            for z in server.zones:
                if server.zones[z].masters: masters += 1
            return masters

        # Sort server list by number of masters. I.e. masters are preferred.
        for server in sorted(self.servers, key=srv_sort):
            if server.external:
                continue

            server.start(clean=True)

            if not server.running():
                raise Failed("Server '%s' not running" % server.name)

            if not server.listening():
                self.stop(kill=True)
                self.start()

        self.start_tries = 0

    def stop(self, check=True, kill=False):
        '''Stop all servers'''

        for server in self.servers:
            if server.external:
                continue

            if kill:
                server.kill()
            else:
                server.stop(check=check)

    def end(self):
        '''Finish testing'''

        self.stop(check=True)
        params.test = None

    def sleep(self, seconds):
        time.sleep(seconds)

    def rel_sleep(self, seconds):
        timenow = time.time()
        res = timenow - self.rel_time
        if seconds == 0:
            self.rel_time = timenow
        else:
            self.rel_time += seconds
        to_wait = self.rel_time - timenow
        if to_wait > 0:
            self.sleep(to_wait)
        return res

    def zone(self, name, file_name=None, storage=None, version=None, exists=True):

        zone = dnstest.zonefile.ZoneFile(self.zones_dir)
        zone.set_name(name)

        if storage is ".":
            src_dir = self.data_dir
        elif storage:
            src_dir = storage
        else:
            src_dir = params.common_data_dir

        zone.set_file(file_name=file_name, storage=src_dir, version=version,
                      exists=exists)

        return [zone]

    def zone_rnd(self, number, dnssec=None, nsec3=None, records=None, serial=None):
        zones = list()

        # Generate unique zone names.
        names = zone_generate.main(["-n", number]).split()
        for name in names:
            zone = dnstest.zonefile.ZoneFile(self.zones_dir)
            zone.set_name(name)
            zone.gen_file(dnssec=dnssec, nsec3=nsec3, records=records,
                          serial=serial)
            zones.append(zone)

        return zones

    def link(self, zones, master, slave=None, ddns=False, ixfr=False):
        for zone in zones:
            if master not in self.servers:
                raise Failed("Server is out of testing scope")
            master.set_master(zone, slave, ddns, ixfr)

            if slave:
                if slave not in self.servers:
                    raise Failed("Server is out of testing scope")
                slave.set_slave(zone, master, ddns, ixfr)

    def _canonize_record(self, rtype, record):
        ''':-(('''
        item_owner_split = record.strip().split(" ", 1)

        if rtype in [dns.rdatatype.SOA, dns.rdatatype.NS, dns.rdatatype.CNAME, \
                     dns.rdatatype.PTR, dns.rdatatype.DNAME, dns.rdatatype.SOA, \
                     dns.rdatatype.MINFO, dns.rdatatype.RP, dns.rdatatype.MX, \
                     dns.rdatatype.AFSDB, dns.rdatatype.RT, dns.rdatatype.KX, \
                     dns.rdatatype.SRV, dns.rdatatype.NSEC]:
            item_data = item_owner_split[1].lower()
        # pythondns prints signer's as @
        #elif rtype in [dns.rdatatype.RRSIG]:
        #    item_dname_split = item_owner_split[1].rsplit(" ", 1)
        #    item_data = item_dname_split[0].lower() + " " + item_dname_split[1]
        elif rtype in [dns.rdatatype.NAPTR]:
            item_dname_split = item_owner_split[1].rsplit(" ", 1)
            item_data = item_dname_split[0] + " " + item_dname_split[1].lower()
        else:
            item_data = item_owner_split[1]

        return item_owner_split[0].lower() + " " + item_data

    def _axfr_records(self, resp, zone):
        unique = set()
        records = list()

        for msg in resp.resp:
            for rrset in msg.answer:
                rrs = rrset.to_text(origin=dns.name.from_text(zone.name),
                                    relativize=False).split("\n")

                for rr in rrs:
                    item_lower = self._canonize_record(rrset.rdtype, rr.strip())

                    if item_lower in unique and rrset.rdtype != dns.rdatatype.SOA:
                        detail_log("!Duplicate record server='%s':" % server.name)
                        detail_log("  %s" % item_lower)
                        continue

                    unique.add(item_lower)
                    records.append(item_lower)

        return unique, records

    def _axfr_diff_resp(self, unique1, rrset1s, unique2, rrsets2, server1, server2):
        diff1 = sorted(list(unique1 - unique2))
        if diff1:
            set_err("AXFR DIFF")
            detail_log("!Extra records server='%s':" % server1.name)
            for record in diff1:
                detail_log("  %s" % record)

        diff2 = sorted(list(unique2 - unique1))
        if diff2:
            set_err("AXFR DIFF")
            detail_log("!Extra records server='%s':" % server2.name)
            for record in diff2:
                detail_log("  %s" % record)

    def _axfr_diff(self, server1, server2, zone):
        unique1, rrsets1 = self._axfr_records(server1.dig(zone.name, "AXFR", log_no_sep=True), zone)
        unique2, rrsets2 = self._axfr_records(server2.dig(zone.name, "AXFR", log_no_sep=True), zone)

        self._axfr_diff_resp(unique1, rrsets1, unique2, rrsets2, server1, server2)

    class IxfrChange():
        def __init__(self):
            self.soa_old = None
            self.soa_new = None
            self.removed = list()
            self.added = list()

        def rem(self, record):
            self.removed.append(record)

        def add(self, record):
            self.added.append(record)

        def sort(self):
            self.removed.sort()
            self.added.sort()

        def cmp(self, other):
            if self.soa_old != other.soa_old:
                set_err("IXFR CHANGE DIFF")
                detail_log("!Different remove SOA:")
                detail_log("  %s" % self.soa_old)
                detail_log("  %s" % other.soa_old)

            if len(self.removed) != len(other.removed):
                set_err("IXFR CHANGE DIFF")
                detail_log("!Number of remove records:")
                detail_log("  (%i) != (%i)" %
                           (len(self.removed), len(other.removed)))

            for rem1, rem2 in zip(self.removed, other.removed):
                if rem1 != rem2:
                    set_err("IXFR CHANGE DIFF")
                    detail_log("!Different remove records:")
                    detail_log("  %s" % rem1)
                    detail_log("  %s" % rem2)

            if self.soa_new != other.soa_new:
                set_err("IXFR CHANGE DIFF")
                detail_log("!Different add SOA:")
                detail_log("  %s" % self.soa_new)
                detail_log("  %s" % other.soa_new)

            if len(self.added) != len(other.added):
                set_err("IXFR CHANGE DIFF")
                detail_log("!Number of add records:")
                detail_log("  (%i) != (%i)" %
                           (len(self.added), len(other.added)))

            for add1, add2 in zip(self.added, other.added):
                if add1 != add2:
                    set_err("IXFR CHANGE DIFF")
                    detail_log("!Different add records:")
                    detail_log("  %s" % add1)
                    detail_log("  %s" % add2)

    def _ixfr_changes(self, server, zone, serial, udp):
        soa = None
        changes = list()

        resp = server.dig(zone.name, "IXFR", log_no_sep=True, serial=serial,
                          udp=udp)

        change = Test.IxfrChange()
        for msg in resp.resp:
            for rrset in msg.answer:
                records = rrset.to_text(origin=dns.name.from_text(zone.name),
                                    relativize=False).split("\n")
                for record in records:
                    item_lower = self._canonize_record(rrset.rdtype, record.strip())

                    if rrset.rdtype == dns.rdatatype.SOA:
                        if not soa: # IXFR leading SOA.
                            soa = item_lower
                            continue

                        if not change.soa_old: # Remove change section.
                            change.soa_old = item_lower
                            continue

                        if not change.soa_new: # Add change section.
                            change.soa_new = item_lower
                            continue

                        # Next change -> store the actual one.
                        change.sort()
                        changes.append(change)
                        change = Test.IxfrChange()
                        change.soa_old = item_lower
                    else:
                        if not soa:
                            set_err("IXFR FORMAT")
                            detail_log("!Missing leading SOA zone='%s', " \
                                       "server='%s' before:" %
                                       (zone.name, server.name))
                            detail_log("  %s" % item_lower)

                        if not change.soa_old:
                            set_err("IXFR FORMAT")
                            detail_log("!Expected SOA zone='%s', server='%s' " \
                                       "before:" %
                                       (zone.name, server.name))
                            detail_log("  %s" % item_lower)

                        if not change.soa_new:
                            change.rem(item_lower)
                        else:
                            change.add(item_lower)

        if not soa:
            set_err("IXFR FORMAT")
            detail_log("!Missing leading SOA zone='%s', server='%s'" %
                       (zone.name, server.name))
        elif change.removed or change.added:
            set_err("IXFR FORMAT")
            detail_log("!Missing trailing SOA zone='%s', server='%s'" %
                       (zone.name, server.name))
        elif change.soa_old and change.soa_old != soa:
            set_err("IXFR FORMAT")
            detail_log("!Trailing SOA differs from the leading one " \
                       "zone='%s', server='%s'" %
                       (zone.name, server.name))

        return soa, changes

    def _ixfr_diff(self, server1, server2, zone, serial, udp):
        soa1, changes1 = self._ixfr_changes(server1, zone, serial, udp)
        soa2, changes2 = self._ixfr_changes(server2, zone, serial, udp)

        if soa1 != soa2:
            set_err("IXFR DIFF")
            detail_log("!Different leading SOA records:")
            detail_log("  %s" % soa1)
            detail_log("  %s" % soa2)

        if len(changes1) != len(changes2):
            set_err("IXFR DIFF")
            detail_log("!Number of changes:")
            detail_log("  (server='%s', num='%i') != (server='%s', num='%i')" %
                       (server1.name, len(changes1),
                        server2.name, len(changes2)))

        for change1, change2 in zip(changes1, changes2):
            change1.cmp(change2)

    def xfr_diff(self, server1, server2, zones, serials=None, udp=False):
        for zone in zones:
            check_log("CHECK %sXFR DIFF %s %s<->%s" % ("I" if serials else "A",
                      zone.name, server1.name, server2.name))
            if serials:
                self._ixfr_diff(server1, server2, zone, serials[zone.name], udp)
            else:
                self._axfr_diff(server1, server2, zone)

        detail_log(SEP)

    def axfr_diff_resp(self, resp1, resp2, server1, server2, zone):
        unique1, rrsets1 = self._axfr_records(resp1, zone)
        unique2, rrsets2 = self._axfr_records(resp2, zone)

        self._axfr_diff_resp(unique1, rrsets1, unique2, rrsets2, server1, server2)

    def check_axfr_style_ixfr(self, server, zone_name, serial):
        resp_ixfr = server.dig(zone_name, "IXFR", serial=serial)
        resp_axfr = server.dig(zone_name, "AXFR")

        resp_ixfr.check_axfr_style_ixfr(resp_axfr)

